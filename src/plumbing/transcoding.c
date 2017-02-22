/**
 *  Transcoding
 *  Copyright (C) 2013 John Törnblom
 *
 *  This program is free software: you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation, either version 3 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <unistd.h>
#include <libavformat/avformat.h>
#include <libavcodec/avcodec.h>
#include <libavfilter/avfiltergraph.h>
#include <libavfilter/buffersink.h>
#include <libavfilter/buffersrc.h>
#include <libavutil/opt.h>
#include <libavresample/avresample.h>
#include <libavutil/opt.h>
#include <libavutil/audio_fifo.h>
#include <libavutil/dict.h>
#include <libavutil/pixdesc.h>

#if LIBAVUTIL_VERSION_MICRO >= 100 /* FFMPEG */
#define USING_FFMPEG 1
#endif

#define OLD_FILTER		0
#define OLD_ENCODER		0
#define USE_THREADING   1
#define EXIT_STAGE_CONDITION_SHIFT  16

#include "tvheadend.h"
#include "settings.h"
#include "streaming.h"
#include "service.h"
#include "packet.h"
#include "transcoding.h"
#include "libav.h"
#include "parsers/bitstream.h"
#include "parsers/parser_avc.h"

#define NUMBER_OF_VIDEO_STAGES		3
#define NUMBER_OF_FILTER_STAGES		1

LIST_HEAD(transcoder_stream_list, transcoder_stream);

struct transcoder;

typedef enum {
	TS_ENCODER_STAGE = 0,
	TS_DECODER_STAGE,
	TS_FILTER_STAGE
} stage_type_t;

typedef struct transcoder_stream {
  int                           ts_index;
  streaming_component_type_t    ts_type;
  streaming_target_t           *ts_target;
  LIST_ENTRY(transcoder_stream) ts_link;
  int                           ts_first;
  int                           ts_stages;
  pktbuf_t                     *ts_input_gh;

  void (*ts_handle_pkt) (struct transcoder *, struct transcoder_stream *, th_pkt_t *);
  void (*ts_destroy)    (struct transcoder *, struct transcoder_stream *);
} transcoder_stream_t;


typedef struct audio_stream {
  transcoder_stream_t;

  AVCodecContext *aud_ictx;
  AVCodec        *aud_icodec;

  AVCodecContext *aud_octx;
  AVCodec        *aud_ocodec;

  uint64_t        aud_dec_pts;
  uint64_t        aud_enc_pts;

  int8_t          aud_channels;
  int32_t         aud_bitrate;

  AVAudioResampleContext *resample_context;
  AVAudioFifo     *fifo;
  int             resample;
  int             resample_is_open;

  enum AVSampleFormat last_sample_fmt;
  int             last_sample_rate;
  uint64_t        last_channel_layout;

} audio_stream_t;

typedef struct avframes_pipeline {
	AVFrame     **vid_frames;
	int         pipeline_size;
	int			push_pointer;
	int			pop_pointer;
	int 		num_of_frames_available;
	int 		stage_timestamp;
} avframes_pipeline_t;

typedef struct tsAVFilterContext {
	int i_width;
	int i_height;
	int o_width;
	int o_height;
	enum AVPixelFormat i_pix_fmt;
	enum AVPixelFormat o_pix_fmt;
	AVRational time_base;
	AVRational sample_aspect_ratio;
} tsAVFilterContext_t;

struct video_stream;

typedef struct video_stage {
	pthread_t				thread;
	pthread_cond_t			*condition_sync;
	pthread_mutex_t			*condition_mutex;
	struct video_stream 	*vs;
	stage_type_t			 type;
	struct video_stage      *prev;
	struct video_stage      *next;
	union stage {
		struct decoder {
			AVCodecContext			*vid_ictx;
			AVCodec					*vid_icodec;
    		AVPacket				packet;
    		avframes_pipeline_t     *output_pipeline;
		} decoder;
		struct encoder {
			AVCodecContext			*vid_octx;
			AVCodec					*vid_ocodec;
			AVPacket				 packet;
			avframes_pipeline_t     *input_pipeline;
			int 					 pkt_duration;
			uint8_t 				 pkt_commercial;
			uint8_t 				 pkt_componentindex;
			uint8_t 				 pkt_field;
			uint16_t 				 pkt_aspect_num;
			uint16_t 				 pkt_aspect_den;
		} encoder;
		struct filter {
			AVFilterGraph           *flt_graph;
			AVFilterContext         *flt_bufsinkctx;
			AVFilterContext         *flt_bufsrcctx;
			tsAVFilterContext_t      fctx;
			avframes_pipeline_t     *input_pipeline;
			avframes_pipeline_t     *output_pipeline;
		} filter;
	} *stage;
	int number_of_stages;
	int this_stage_number;
} video_stage_t;

typedef struct video_stream {
  transcoder_stream_t;
  video_stage_t				 *video_stages;
  pthread_cond_t			*condition_sync;
  pthread_mutex_t			*condition_mutex;

  int16_t                    vid_width;
  int16_t                    vid_height;
  int						 stage_run_mask;
  int                        vid_first_sent;
  int                        vid_first_encoded;
  th_pkt_t                  *vid_first_pkt;
  struct transcoder			*t;
} video_stream_t;


typedef struct subtitle_stream {
  transcoder_stream_t;

  AVCodecContext            *sub_ictx;
  AVCodec                   *sub_icodec;

  AVCodecContext            *sub_octx;
  AVCodec                   *sub_ocodec;
} subtitle_stream_t;



typedef struct transcoder {
  streaming_target_t  t_input;  // must be first
  streaming_target_t *t_output;

  uint32_t            t_id;

  transcoder_props_t            t_props;
  struct transcoder_stream_list t_stream_list;
} transcoder_t;



#define WORKING_ENCODER(x) \
  ((x) == AV_CODEC_ID_H264 || (x) == AV_CODEC_ID_MPEG2VIDEO || \
   (x) == AV_CODEC_ID_VP8  || /* (x) == AV_CODEC_ID_VP9 || */ \
   (x) == AV_CODEC_ID_HEVC || (x) == AV_CODEC_ID_AAC || \
   (x) == AV_CODEC_ID_MP2  || (x) == AV_CODEC_ID_VORBIS)

/**
 *
 */
static inline int
shortid(transcoder_t *t)
{
  return t->t_id & 0xffff;
}

static inline struct timespec timeDiff(struct timespec oldTime, struct timespec time)
{
    if (time.tv_nsec < oldTime.tv_nsec)
        return (struct timespec){
            tv_sec: time.tv_sec - 1 - oldTime.tv_sec,
            tv_nsec: 1E9 + time.tv_nsec - oldTime.tv_nsec
        };
    else
        return (struct timespec){
            tv_sec: time.tv_sec - oldTime.tv_sec,
            tv_nsec: time.tv_nsec - oldTime.tv_nsec
        };
}

static inline void
transcoder_stream_invalidate(transcoder_stream_t *ts)
{
  ts->ts_index = 0;
}

static AVCodecContext *
avcodec_alloc_context3_tvh(const AVCodec *codec)
{
  AVCodecContext *ctx = avcodec_alloc_context3(codec);
  if (ctx) {
    ctx->strict_std_compliance = FF_COMPLIANCE_EXPERIMENTAL;
  }
  return ctx;
}

static char *const
get_error_text(const int error)
{
  static char error_buffer[255];
  av_strerror(error, error_buffer, sizeof(error_buffer));
  return error_buffer;
}

static int
transcode_opt_set_int(transcoder_t *t, transcoder_stream_t *ts,
                      void *ctx, const char *opt,
                      int64_t val, int abort)
{
  int opt_error;
  if ((opt_error = av_opt_set_int(ctx, opt, val, 0)) != 0) {
    tvherror(LS_TRANSCODE, "%04X: Could not set option %s (error '%s')",
             shortid(t), opt, get_error_text(opt_error));
    if (abort)
      transcoder_stream_invalidate(ts);
    return -1;
  }
  return 0;
}

static void
av_dict_set_int__(AVDictionary **opts, const char *key, int64_t val, int flags)
{
  char buf[32];
  snprintf(buf, sizeof(buf), "%"PRId64, val);
  av_dict_set(opts, key, buf, flags);
}

/**
 * get best effort sample rate
 */
static int
transcode_get_sample_rate(int rate, AVCodec *codec)
{
  /* if codec only supports certain rates, check if rate is available */
  if (codec->supported_samplerates) {
    /* Find if we have a matching sample_rate */
    int acount = 0;
    int rate_alt = 0;
    while (codec->supported_samplerates[acount] > 0) {
      if (codec->supported_samplerates[acount] == rate) {
        /* original rate supported by codec */
        return rate;
      }

      /* check for highest available rate smaller that the original rate */
      if (codec->supported_samplerates[acount] > rate_alt &&
          codec->supported_samplerates[acount] < rate) {
        rate_alt = codec->supported_samplerates[acount];
      }
      acount++;
    }

    return rate_alt;
  }


  return rate;
}

/**
 * get best effort sample format
 */
static enum AVSampleFormat
transcode_get_sample_fmt(enum AVSampleFormat fmt, AVCodec *codec)
{
  /* if codec only supports certain formats, check if selected format is available */
  if (codec->sample_fmts) {
    /* Find if we have a matching sample_fmt */
    int acount = 0;
    while (codec->sample_fmts[acount] > AV_SAMPLE_FMT_NONE) {
      if (codec->sample_fmts[acount] == fmt) {
        /* original format supported by codec */
        return fmt;
      }
      acount++;
    }

    /* use first supported sample format */
    if (acount > 0) {
      return codec->sample_fmts[0];
    } else {
      return AV_SAMPLE_FMT_NONE;
    }
  }

  return fmt;
}

/**
 * get best effort channel layout
 */
static uint64_t
transcode_get_channel_layout(int *channels, AVCodec *codec)
{
  uint64_t channel_layout = AV_CH_LAYOUT_STEREO;

  /* use channel layout based on input field */
  switch (*channels) {
  case 1: channel_layout = AV_CH_LAYOUT_MONO;     break;
  case 2: channel_layout = AV_CH_LAYOUT_STEREO;   break;
  case 3: channel_layout = AV_CH_LAYOUT_SURROUND; break;
  case 4: channel_layout = AV_CH_LAYOUT_QUAD;     break;
  case 5: channel_layout = AV_CH_LAYOUT_5POINT0;  break;
  case 6: channel_layout = AV_CH_LAYOUT_5POINT1;  break;
  case 7: channel_layout = AV_CH_LAYOUT_6POINT1;  break;
  case 8: channel_layout = AV_CH_LAYOUT_7POINT1;  break;
  }

  /* if codec only supports certain layouts, check if selected layout is available */
  if (codec->channel_layouts) {
    int acount = 0;
    uint64_t channel_layout_def = av_get_default_channel_layout(*channels);
    uint64_t channel_layout_alt = 0;

    while (codec->channel_layouts[acount] > 0) {
      if (codec->channel_layouts[acount] == channel_layout) {
        /* original layout supported by codec */
        return channel_layout;
      }

      /* check for best matching layout with same or less number of channels */
      if (av_get_channel_layout_nb_channels(codec->channel_layouts[acount]) <= *channels) {
        if (av_get_channel_layout_nb_channels(codec->channel_layouts[acount]) >
            av_get_channel_layout_nb_channels(channel_layout_alt)) {
          /* prefer layout with more channels */
          channel_layout_alt = codec->channel_layouts[acount];
        } else if (av_get_channel_layout_nb_channels(codec->channel_layouts[acount]) ==
                   av_get_channel_layout_nb_channels(channel_layout_alt) &&
                   codec->channel_layouts[acount] == channel_layout_def) {
          /* prefer default layout for number of channels over alternative layout */
          channel_layout_alt = channel_layout_def;
        }
      }

      acount++;
    }

    if (channel_layout_alt) {
      channel_layout = channel_layout_alt;
      *channels = av_get_channel_layout_nb_channels(channel_layout_alt);
    } else {
      channel_layout = 0;
      *channels = 0;
    }
  }

  return channel_layout;
}

/**
 *
 */
static AVCodec *
transcoder_get_decoder(transcoder_t *t, streaming_component_type_t ty)
{
  enum AVCodecID codec_id;
  AVCodec *codec;

  /* the MP4A and AAC packet format is same, reduce to one type */
  if (ty == SCT_MP4A)
    ty = SCT_AAC;

  codec_id = streaming_component_type2codec_id(ty);
  if (codec_id == AV_CODEC_ID_NONE) {
    tvherror(LS_TRANSCODE, "%04X: Unsupported input codec %s",
	     shortid(t), streaming_component_type2txt(ty));
    return NULL;
  }

  codec = avcodec_find_decoder(codec_id);
  if (!codec) {
    tvherror(LS_TRANSCODE, "%04X: Unable to find %s decoder",
	     shortid(t), streaming_component_type2txt(ty));
    return NULL;
  }

  tvhtrace(LS_TRANSCODE, "%04X: Using decoder %s", shortid(t), codec->name);

  return codec;
}

/**
 *
 */
static AVCodec *
transcoder_get_decoder_video(transcoder_t *t, streaming_component_type_t ty)
{
  enum AVCodecID codec_id;
  AVCodec *codec;

  /* the MP4A and AAC packet format is same, reduce to one type */
  if (ty == SCT_MP4A)
    ty = SCT_AAC;

  codec_id = streaming_component_type2codec_id(ty);
  if (codec_id == AV_CODEC_ID_NONE) {
    tvherror(LS_TRANSCODE, "%04X: Unsupported input codec %s",
	     shortid(t), streaming_component_type2txt(ty));
    return NULL;
  }
  (void)codec_id;
  codec = avcodec_find_decoder_by_name("mpeg2video");
  if (!codec) {
    tvherror(LS_TRANSCODE, "%04X: Unable to find %s decoder",
	     shortid(t), streaming_component_type2txt(ty));
    return NULL;
  }

  tvhtrace(LS_TRANSCODE, "%04X: Using decoder %s", shortid(t), codec->name);

  return codec;
}
/**
 *
 */
static AVCodec *
transcoder_get_encoder(transcoder_t *t, const char *codec_name)
{
  AVCodec *codec;

  codec = avcodec_find_encoder_by_name(codec_name);
  if (!codec) {
    tvherror(LS_TRANSCODE, "%04X: Unable to find %s encoder",
             shortid(t), codec_name);
    return NULL;
  }
  tvhtrace(LS_TRANSCODE, "%04X: Using encoder %s", shortid(t), codec->name);

  return codec;
}


/**
 *
 */
static void
transcoder_stream_packet(transcoder_t *t, transcoder_stream_t *ts, th_pkt_t *pkt)
{
  streaming_message_t *sm;

  tvhtrace(LS_TRANSCODE, "%04X: deliver copy (pts = %" PRIu64 ")",
           shortid(t), pkt->pkt_pts);
  sm = streaming_msg_create_pkt(pkt);
  streaming_target_deliver2(ts->ts_target, sm);
  pkt_ref_dec(pkt);
}


/**
 *
 */
static void
transcoder_stream_subtitle(transcoder_t *t, transcoder_stream_t *ts, th_pkt_t *pkt)
{
  //streaming_message_t *sm;
  AVCodec *icodec;
  AVCodecContext *ictx;
  AVPacket packet;
  AVSubtitle sub;
  int length, got_subtitle;

  subtitle_stream_t *ss = (subtitle_stream_t*)ts;

  ictx = ss->sub_ictx;
  //octx = ss->sub_octx;

  icodec = ss->sub_icodec;
  //ocodec = ss->sub_ocodec;


  if (!avcodec_is_open(ictx)) {
    if (avcodec_open2(ictx, icodec, NULL) < 0) {
      tvherror(LS_TRANSCODE, "%04X: Unable to open %s decoder",
               shortid(t), icodec->name);
      transcoder_stream_invalidate(ts);
      return;
    }
  }

  av_init_packet(&packet);
  packet.data     = pktbuf_ptr(pkt->pkt_payload);
  packet.size     = pktbuf_len(pkt->pkt_payload);
  packet.pts      = pkt->pkt_pts;
  packet.dts      = pkt->pkt_dts;
  packet.duration = pkt->pkt_duration;

  memset(&sub, 0, sizeof(sub));

  length = avcodec_decode_subtitle2(ictx,  &sub, &got_subtitle, &packet);
  if (length <= 0) {
    if (length == AVERROR_INVALIDDATA) goto cleanup;
    tvherror(LS_TRANSCODE, "%04X: Unable to decode subtitle (%d, %s)",
             shortid(t), length, get_error_text(length));
    goto cleanup;
  }

  if (!got_subtitle)
    goto cleanup;

  //TODO: encoding

 cleanup:
  av_free_packet(&packet);
  avsubtitle_free(&sub);
}

static void
create_adts_header(pktbuf_t *pb, int sri, int channels)
{
   bitstream_t bs;

   /* 7 bytes of ADTS header */
   init_wbits(&bs, pktbuf_ptr(pb), 56);

   put_bits(&bs, 0xfff, 12); // Sync marker
   put_bits(&bs, 0, 1);      // ID 0 = MPEG 4, 1 = MPEG 2
   put_bits(&bs, 0, 2);      // Layer
   put_bits(&bs, 1, 1);      // Protection absent
   put_bits(&bs, 1, 2);      // AOT, 1 = AAC LC
   put_bits(&bs, sri, 4);
   put_bits(&bs, 1, 1);      // Private bit
   put_bits(&bs, channels, 3);
   put_bits(&bs, 1, 1);      // Original
   put_bits(&bs, 1, 1);      // Copy

   put_bits(&bs, 1, 1);      // Copyright identification bit
   put_bits(&bs, 1, 1);      // Copyright identification start
   put_bits(&bs, pktbuf_len(pb), 13);
   put_bits(&bs, 0x7ff, 11); // Buffer fullness
   put_bits(&bs, 0, 2);      // RDB in frame
}

/**
 *
 */
static void
transcoder_stream_audio(transcoder_t *t, transcoder_stream_t *ts, th_pkt_t *pkt)
{
  AVCodec *icodec, *ocodec;
  AVCodecContext *ictx, *octx;
  AVPacket packet;
  int length;
  streaming_message_t *sm;
  th_pkt_t *n;
  audio_stream_t *as = (audio_stream_t*)ts;
  int got_frame, got_packet_ptr;
  AVFrame *frame = av_frame_alloc();
  char layout_buf[100];
  uint8_t *d;

  ictx = as->aud_ictx;
  octx = as->aud_octx;

  icodec = as->aud_icodec;
  ocodec = as->aud_ocodec;

  av_init_packet(&packet);

  if (!avcodec_is_open(ictx)) {
    if (icodec->id == AV_CODEC_ID_AAC || icodec->id == AV_CODEC_ID_VORBIS) {
      d = pktbuf_ptr(pkt->pkt_payload);
      if (icodec->id == AV_CODEC_ID_AAC && d && pktbuf_len(pkt->pkt_payload) > 2 &&
          d[0] == 0xff && (d[1] & 0xf0) == 0xf0) {
        /* DTS packets have all info */
      } else if (ts->ts_input_gh) {
        ictx->extradata_size = pktbuf_len(ts->ts_input_gh);
        ictx->extradata = av_malloc(ictx->extradata_size);
        memcpy(ictx->extradata,
               pktbuf_ptr(ts->ts_input_gh), pktbuf_len(ts->ts_input_gh));
        tvhtrace(LS_TRANSCODEA, "%04X: copy meta data for %s (len %zd)",
                 shortid(t), icodec->id == AV_CODEC_ID_AAC ? "AAC" : "VORBIS",
                 pktbuf_len(ts->ts_input_gh));
      } else {
        tvherror(LS_TRANSCODEA, "%04X: missing meta data for %s",
                 shortid(t), icodec->id == AV_CODEC_ID_AAC ? "AAC" : "VORBIS");
      }
    }

    if (avcodec_open2(ictx, icodec, NULL) < 0) {
      tvherror(LS_TRANSCODEA, "%04X: Unable to open %s decoder",
               shortid(t), icodec->name);
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

    as->aud_dec_pts = pkt->pkt_pts;
  }

  if (pkt->pkt_pts > as->aud_dec_pts) {
    tvhwarn(LS_TRANSCODEA, "%04X: Detected framedrop in audio", shortid(t));
    as->aud_enc_pts += (pkt->pkt_pts - as->aud_dec_pts);
    as->aud_dec_pts += (pkt->pkt_pts - as->aud_dec_pts);
  }

  packet.data     = pktbuf_ptr(pkt->pkt_payload);
  packet.size     = pktbuf_len(pkt->pkt_payload);
  packet.pts      = pkt->pkt_pts;
  packet.dts      = pkt->pkt_dts;
  packet.duration = pkt->pkt_duration;

  length = avcodec_decode_audio4(ictx, frame, &got_frame, &packet);
  av_free_packet(&packet);

  tvhtrace(LS_TRANSCODEA, "%04X: audio decode: consumed=%d size=%zu, got=%d, pts=%" PRIi64,
           shortid(t), length, pktbuf_len(pkt->pkt_payload), got_frame, pkt->pkt_pts);

  if (length < 0) {
    if (length == AVERROR_INVALIDDATA) goto cleanup;
    tvherror(LS_TRANSCODEA, "%04X: Unable to decode audio (%d, %s)",
             shortid(t), length, get_error_text(length));
    transcoder_stream_invalidate(ts);
    goto cleanup;
  }

  if (!got_frame) {
    tvhtrace(LS_TRANSCODEA, "%04X: Did not have a full frame in the packet", shortid(t));
    goto cleanup;
  }

  if (length != pktbuf_len(pkt->pkt_payload))
    tvhwarn(LS_TRANSCODEA,
            "%04X: undecoded data (in=%zu, consumed=%d)",
            shortid(t), pktbuf_len(pkt->pkt_payload), length);

  if (!avcodec_is_open(octx)) {
    as->aud_enc_pts       = pkt->pkt_pts;
    octx->sample_rate     = transcode_get_sample_rate(ictx->sample_rate, ocodec);
    octx->sample_fmt      = transcode_get_sample_fmt(ictx->sample_fmt, ocodec);
    octx->time_base       = ictx->time_base;
    octx->channels        = as->aud_channels ? as->aud_channels : ictx->channels;
    octx->channel_layout  = transcode_get_channel_layout(&octx->channels, ocodec);
    octx->bit_rate        = as->aud_bitrate  ? as->aud_bitrate  : 0;
    octx->flags          |= CODEC_FLAG_GLOBAL_HEADER;

    if (!octx->sample_rate) {
      tvherror(LS_TRANSCODEA, "%04X: audio encoder has no suitable sample rate!", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    } else {
      tvhdebug(LS_TRANSCODEA, "%04X: using audio sample rate %d",
                          shortid(t), octx->sample_rate);
    }

    if (octx->sample_fmt == AV_SAMPLE_FMT_NONE) {
      tvherror(LS_TRANSCODEA, "%04X: audio encoder has no suitable sample format!", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    } else {
      tvhdebug(LS_TRANSCODEA, "%04X: using audio sample format %s",
                          shortid(t), av_get_sample_fmt_name(octx->sample_fmt));
    }

    if (!octx->channel_layout) {
      tvherror(LS_TRANSCODEA, "%04X: audio encoder has no suitable channel layout!", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    } else {
      av_get_channel_layout_string(layout_buf, sizeof (layout_buf), octx->channels, octx->channel_layout);
      tvhdebug(LS_TRANSCODEA, "%04X: using audio channel layout %s",
                          shortid(t), layout_buf);
    }

    // Set flags and quality settings, if no bitrate was specified.
    // The MPEG2 encoder only supports encoding with fixed bitrate.
    // All AAC encoders should support encoding with fixed bitrate,
    // but some don't support encoding with global_quality (vbr).
    // All vorbis encoders support encoding with global_quality (vbr),
    // but the built in vorbis encoder doesn't support fixed bitrate.
    switch (ts->ts_type) {
    case SCT_MPEG2AUDIO:
      // use 96 kbit per channel as default
      if (octx->bit_rate == 0) {
        octx->bit_rate = octx->channels * 96000;
      }
      break;

    case SCT_AAC:
      octx->flags |= CODEC_FLAG_BITEXACT;
      // use 64 kbit per channel as default
      if (octx->bit_rate == 0) {
        octx->bit_rate = octx->channels * 64000;
      }
      break;

    case SCT_VORBIS:
      // use vbr with quality setting as default
      // and also use a user specified bitrate < 16 kbit as quality setting
      if (octx->bit_rate == 0) {
        octx->flags |= CODEC_FLAG_QSCALE;
        octx->global_quality = 4 * FF_QP2LAMBDA;
      } else if (t->t_props.tp_abitrate < 16) {
        octx->flags |= CODEC_FLAG_QSCALE;
        octx->global_quality = t->t_props.tp_abitrate * FF_QP2LAMBDA;
        octx->bit_rate = 0;
      }
      break;

    default:
      break;
    }

    if (avcodec_open2(octx, ocodec, NULL) < 0) {
      tvherror(LS_TRANSCODEA, "%04X: Unable to open %s encoder",
               shortid(t), ocodec->name);
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

    as->fifo = av_audio_fifo_alloc(octx->sample_fmt, octx->channels, 1);
    if (!as->fifo) {
      tvherror(LS_TRANSCODEA, "%04X: Could not allocate fifo", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

    as->resample_context    = NULL;

    as->last_sample_rate    = ictx->sample_rate;
    as->last_sample_fmt     = ictx->sample_fmt;
    as->last_channel_layout = ictx->channel_layout;
  }

  /* check for changed input format and close resampler, if changed */
  if (as->last_sample_rate    != ictx->sample_rate    ||
      as->last_sample_fmt     != ictx->sample_fmt     ||
      as->last_channel_layout != ictx->channel_layout) {
    tvhdebug(LS_TRANSCODEA, "%04X: audio input format changed", shortid(t));

    as->last_sample_rate    = ictx->sample_rate;
    as->last_sample_fmt     = ictx->sample_fmt;
    as->last_channel_layout = ictx->channel_layout;

    if (as->resample_context) {
      tvhdebug(LS_TRANSCODEA, "%04X: stopping audio resampling", shortid(t));
      avresample_free(&as->resample_context);
      as->resample_context = NULL;
      as->resample_is_open = 0;
    }
  }

  as->resample = (ictx->channel_layout != octx->channel_layout) ||
                 (ictx->sample_fmt     != octx->sample_fmt)     ||
                 (ictx->sample_rate    != octx->sample_rate);

  if (as->resample) {
    if (!as->resample_context) {
      if (!(as->resample_context = avresample_alloc_context())) {
        tvherror(LS_TRANSCODEA, "%04X: Could not allocate resample context", shortid(t));
        transcoder_stream_invalidate(ts);
        goto cleanup;
      }

      // resample audio
      tvhdebug(LS_TRANSCODEA, "%04X: starting audio resampling", shortid(t));

      av_get_channel_layout_string(layout_buf, sizeof (layout_buf), ictx->channels, ictx->channel_layout);
      tvhdebug(LS_TRANSCODEA, "%04X: IN : channel_layout=%s, rate=%d, fmt=%s, bitrate=%"PRId64,
               shortid(t), layout_buf, ictx->sample_rate,
               av_get_sample_fmt_name(ictx->sample_fmt), (int64_t)ictx->bit_rate);

      av_get_channel_layout_string(layout_buf, sizeof (layout_buf), octx->channels, octx->channel_layout);
      tvhdebug(LS_TRANSCODEA, "%04X: OUT: channel_layout=%s, rate=%d, fmt=%s, bitrate=%"PRId64,
               shortid(t), layout_buf, octx->sample_rate,
               av_get_sample_fmt_name(octx->sample_fmt), (int64_t)octx->bit_rate);

      if (transcode_opt_set_int(t, ts, as->resample_context,
                                "in_channel_layout", ictx->channel_layout, 1))
        goto cleanup;
      if (transcode_opt_set_int(t, ts, as->resample_context,
                                "out_channel_layout", octx->channel_layout, 1))
        goto cleanup;
      if (transcode_opt_set_int(t, ts, as->resample_context,
                                "in_sample_rate", ictx->sample_rate, 1))
        goto cleanup;
      if (transcode_opt_set_int(t, ts, as->resample_context,
                                "out_sample_rate", octx->sample_rate, 1))
        goto cleanup;
      if (transcode_opt_set_int(t, ts, as->resample_context,
                                "in_sample_fmt", ictx->sample_fmt, 1))
        goto cleanup;
      if (transcode_opt_set_int(t, ts, as->resample_context,
                                "out_sample_fmt", octx->sample_fmt, 1))
        goto cleanup;
      if (avresample_open(as->resample_context) < 0) {
        tvherror(LS_TRANSCODEA, "%04X: Error avresample_open", shortid(t));
        transcoder_stream_invalidate(ts);
        goto cleanup;
      }
      as->resample_is_open = 1;
    }

    uint8_t **output = alloca(octx->channels * sizeof(uint8_t *));

    if (av_samples_alloc(output, NULL, octx->channels, frame->nb_samples, octx->sample_fmt, 1) < 0) {
      tvherror(LS_TRANSCODEA, "%04X: av_resamples_alloc failed", shortid(t));
      transcoder_stream_invalidate(ts);
      goto scleanup;
    }

    length = avresample_convert(as->resample_context, NULL, 0, frame->nb_samples,
                                frame->extended_data, 0, frame->nb_samples);
    tvhtrace(LS_TRANSCODEA, "%04X: avresample_convert: %d", shortid(t), length);
    while (avresample_available(as->resample_context) > 0) {
      length = avresample_read(as->resample_context, output, frame->nb_samples);

      if (length > 0) {
        if (av_audio_fifo_realloc(as->fifo, av_audio_fifo_size(as->fifo) + length) < 0) {
          tvherror(LS_TRANSCODEA, "%04X: Could not reallocate FIFO", shortid(t));
          transcoder_stream_invalidate(ts);
          goto scleanup;
        }

        if (av_audio_fifo_write(as->fifo, (void **)output, length) < length) {
          tvherror(LS_TRANSCODEA, "%04X: Could not write to FIFO", shortid(t));
          goto scleanup;
        }
      }
      continue;

scleanup:
      transcoder_stream_invalidate(ts);
      av_freep(&output[0]);
      goto cleanup;
    }

    av_freep(&output[0]);

/*  Need to find out where we are going to do this. Normally at the end.
    int delay_samples = avresample_get_delay(as->resample_context);
    if (delay_samples) {
      tvhdebug(LS_TRANSCODEA, "%d samples in resamples delay buffer.", delay_samples);
      goto cleanup;
    }
*/

  } else {

    if (av_audio_fifo_realloc(as->fifo, av_audio_fifo_size(as->fifo) + frame->nb_samples) < 0) {
      tvherror(LS_TRANSCODEA, "%04X: Could not reallocate FIFO", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

    if (av_audio_fifo_write(as->fifo, (void **)frame->extended_data, frame->nb_samples) < frame->nb_samples) {
      tvherror(LS_TRANSCODEA, "%04X: Could not write to FIFO", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

  }

  as->aud_dec_pts += pkt->pkt_duration;

  while (av_audio_fifo_size(as->fifo) >= octx->frame_size) {
    tvhtrace(LS_TRANSCODEA, "%04X: audio loop: fifo=%d, frame=%d",
             shortid(t), av_audio_fifo_size(as->fifo), octx->frame_size);

    av_frame_free(&frame);
    frame = av_frame_alloc();
    frame->nb_samples = octx->frame_size;
    frame->format = octx->sample_fmt;
#if USING_FFMPEG
    frame->channels = octx->channels;
#endif
    frame->channel_layout = octx->channel_layout;
    frame->sample_rate = octx->sample_rate;
    if (av_frame_get_buffer(frame, 0) < 0) {
      tvherror(LS_TRANSCODEA, "%04X: Could not allocate output frame samples", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

    if ((length = av_audio_fifo_read(as->fifo, (void **)frame->data, octx->frame_size)) != octx->frame_size) {
      tvherror(LS_TRANSCODEA, "%04X: Could not read data from FIFO", shortid(t));
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }

    tvhtrace(LS_TRANSCODEA, "%04X: pre-encode: linesize=%d, samples=%d, pts=%" PRIi64,
             shortid(t), frame->linesize[0], length, as->aud_enc_pts);

    frame->pts = as->aud_enc_pts;
    as->aud_enc_pts += (octx->frame_size * 90000) / octx->sample_rate;

    av_init_packet(&packet);
    packet.data = NULL;
    packet.size = 0;
    length = avcodec_encode_audio2(octx, &packet, frame, &got_packet_ptr);
    tvhtrace(LS_TRANSCODEA, "%04X: encoded: packet=%d, ret=%d, got=%d, pts=%" PRIi64,
             shortid(t), packet.size, length, got_packet_ptr, packet.pts);

    if ((length < 0) || (got_packet_ptr < -1)) {

      tvherror(LS_TRANSCODEA, "%04X: Unable to encode audio (%d:%d)",
               shortid(t), length, got_packet_ptr);
      transcoder_stream_invalidate(ts);
      goto cleanup;

    } else if (got_packet_ptr && packet.pts >= 0) {

      int extra_size = 0;

      if (ts->ts_type == SCT_AAC) {
        /* only if ADTS header is missing, create it */
        if (packet.size < 2 || packet.data[0] != 0xff || (packet.data[1] & 0xf0) != 0xf0)
          extra_size = 7;
      }

      n = pkt_alloc(NULL, packet.size + extra_size, packet.pts, packet.pts);
      memcpy(pktbuf_ptr(n->pkt_payload) + extra_size, packet.data, packet.size);

      n->pkt_componentindex = ts->ts_index;
      n->pkt_channels       = octx->channels;
      n->pkt_sri            = rate_to_sri(octx->sample_rate);
      n->pkt_duration       = packet.duration;

      if (extra_size && ts->ts_type == SCT_AAC)
        create_adts_header(n->pkt_payload, n->pkt_sri, octx->channels);

      if (octx->extradata_size)
        n->pkt_meta = pktbuf_alloc(octx->extradata, octx->extradata_size);

      tvhtrace(LS_TRANSCODEA, "%04X: deliver audio (pts = %" PRIi64 ", delay = %i)",
               shortid(t), n->pkt_pts, octx->delay);
      sm = streaming_msg_create_pkt(n);
      streaming_target_deliver2(ts->ts_target, sm);
      pkt_ref_dec(n);
    }

    av_free_packet(&packet);
  }

 cleanup:

  av_frame_free(&frame);
  av_free_packet(&packet);

  pkt_ref_dec(pkt);
}

/**
 * Parse MPEG2 header, simplifier version (we know what ffmpeg/libav generates
 */
static void
extract_mpeg2_global_data(th_pkt_t *n, uint8_t *data, int len)
{
/*
From: http://en.wikipedia.org/wiki/Elementary_stream
Field Name 	# of bits 	Description
start code				32 	0x000001B3
Horizontal Size				12
Vertical Size				12
Aspect ratio				4
Frame rate code				4
Bit rate				18 	Actual bit rate = bit rate * 400, rounded upwards. Use 0x3FFFF for variable bit rate.
Marker bit				1 	Always 1.
VBV buf size				10 	Size of video buffer verifier = 16*1024*vbv buf size
constrained parameters flag		1
load intra quantizer matrix		1 	If bit set then intra quantizer matrix follows, otherwise use default values.
intra quantizer matrix			0 or 64*8
load non intra quantizer matrix 	1 	If bit set then non intra quantizer matrix follows.
non intra quantizer matrix		0 or 64*8

Minimal of 12 bytes.
*/
  int hs = 12;

  if (len >= hs && RB32(data) == 0x000001b3) {  // SEQ_START_CODE

    // load intra quantizer matrix
    if (data[hs-1] & 0x02) {
      if (hs + 64 < len) return;
      hs += 64;
    }

    // load non intra quantizer matrix
    if (data[hs-1] & 0x01) {
      if (hs + 64 < len) return;
      hs += 64;
    }

    // See if we have the first EXT_START_CODE. Normally 10 bytes
    // https://git.libav.org/?p=libav.git;a=blob;f=libavcodec/mpeg12enc.c;h=3376f1075f4b7582a8e4556e98deddab3e049dab;hb=HEAD#l272
    if (hs + 10 <= len && RB32(data + hs) == 0x000001b5) // EXT_START_CODE
      hs += 10;

    // See if we have the second EXT_START_CODE. Normally 12 bytes
    // https://git.libav.org/?p=libav.git;a=blob;f=libavcodec/mpeg12enc.c;h=3376f1075f4b7582a8e4556e98deddab3e049dab;hb=HEAD#l291
    // ffmpeg libs might have this block missing
    if (hs + 12 <= len && RB32(data + hs) == 0x000001b5) // EXT_START_CODE
      hs += 12;

    // See if we have the second GOP_START_CODE. Normally 31 bits == 4 bytes
    // https://git.libav.org/?p=libav.git;a=blob;f=libavcodec/mpeg12enc.c;h=3376f1075f4b7582a8e4556e98deddab3e049dab;hb=HEAD#l304
    if (hs + 4 <= len && RB32(data + hs) == 0x000001b8) // GOP_START_CODE
      hs += 4;

    n->pkt_meta = pktbuf_alloc(data, hs);
  }
}

/**
 *
 */
static void
send_video_packet(transcoder_t *t, transcoder_stream_t *ts, struct encoder *encoder,
                  AVPacket *epkt, AVCodecContext *octx)
{
  video_stream_t *vs = (video_stream_t*)ts;
  streaming_message_t *sm;
  th_pkt_t *n;

  if (epkt->size <= 0) {
    if (epkt->size) {
      tvherror(LS_TRANSCODE, "%04X: Unable to encode video (%d)", shortid(t), epkt->size);
      transcoder_stream_invalidate(ts);
    }

    return;
  }

  if (!octx->coded_frame)
    return;

  if ((ts->ts_type == SCT_H264 || ts->ts_type == SCT_HEVC) &&
      octx->extradata_size &&
      (ts->ts_first || octx->coded_frame->pict_type == AV_PICTURE_TYPE_I)) {
    n = pkt_alloc(NULL, octx->extradata_size + epkt->size, epkt->pts, epkt->dts);
    memcpy(pktbuf_ptr(n->pkt_payload), octx->extradata, octx->extradata_size);
    memcpy(pktbuf_ptr(n->pkt_payload) + octx->extradata_size, epkt->data, epkt->size);
    ts->ts_first = 0;
  } else {
    n = pkt_alloc(epkt->data, epkt->size, epkt->pts, epkt->dts);
  }

  switch (octx->coded_frame->pict_type) {
  case AV_PICTURE_TYPE_I:
    n->pkt_frametype = PKT_I_FRAME;
    break;

  case AV_PICTURE_TYPE_P:
    n->pkt_frametype = PKT_P_FRAME;
    break;

  case AV_PICTURE_TYPE_B:
    n->pkt_frametype = PKT_B_FRAME;
    break;

  default:
    break;
  }

  n->pkt_duration       = encoder->pkt_duration;
  n->pkt_commercial     = encoder->pkt_commercial;
  n->pkt_componentindex = encoder->pkt_componentindex;
  n->pkt_field          = encoder->pkt_field;
  n->pkt_aspect_num     = encoder->pkt_aspect_num;
  n->pkt_aspect_den     = encoder->pkt_aspect_den;

  if(octx->coded_frame && octx->coded_frame->pts != AV_NOPTS_VALUE) {
    if(n->pkt_dts != PTS_UNSET)
      n->pkt_dts -= n->pkt_pts;

    n->pkt_pts = octx->coded_frame->pts;

    if(n->pkt_dts != PTS_UNSET)
      n->pkt_dts += n->pkt_pts;
  }

  if (octx->extradata_size) {
    n->pkt_meta = pktbuf_alloc(octx->extradata, octx->extradata_size);
  } else {
    if (octx->codec_id == AV_CODEC_ID_MPEG2VIDEO)
      extract_mpeg2_global_data(n, epkt->data, epkt->size);
  }

  tvhtrace(LS_TRANSCODE, "%04X: deliver video (dts = %" PRIu64 ", pts = %" PRIu64 ")", shortid(t), n->pkt_dts, n->pkt_pts);

  if (!vs->vid_first_encoded) {
    vs->vid_first_pkt = n;
    vs->vid_first_encoded = 1;
    return;
  }
  if (vs->vid_first_pkt) {
    if (vs->vid_first_pkt->pkt_dts < n->pkt_dts) {
      sm = streaming_msg_create_pkt(vs->vid_first_pkt);
      streaming_target_deliver2(ts->ts_target, sm);
    } else {
      tvhtrace(LS_TRANSCODE, "%04X: video skip first packet", shortid(t));
    }
    pkt_ref_dec(vs->vid_first_pkt);
    vs->vid_first_pkt = NULL;
  }

  sm = streaming_msg_create_pkt(n);
  streaming_target_deliver2(ts->ts_target, sm);
  pkt_ref_dec(n);

}

/* create a simple deinterlacer-scaler video filter chain */
static int
create_video_filter(struct filter *filter, transcoder_t *t)
{
  AVFilterInOut *flt_inputs, *flt_outputs;
  AVFilter *flt_bufsrc, *flt_bufsink;
  enum AVPixelFormat pix_fmts[] = { 0, AV_PIX_FMT_NONE };
  char opt[128];
  int err;

  err = 1;
  flt_inputs = flt_outputs = NULL;
  flt_bufsrc = flt_bufsink = NULL;

  if (filter->flt_graph)
    avfilter_graph_free(&filter->flt_graph);

  filter->flt_graph = avfilter_graph_alloc();
  if (!filter->flt_graph)
    return err;

  flt_inputs = avfilter_inout_alloc();
  if (!flt_inputs)
    goto out_err;

  flt_outputs = avfilter_inout_alloc();
  if (!flt_outputs)
    goto out_err;

  flt_bufsrc = avfilter_get_by_name("buffer");
  flt_bufsink = avfilter_get_by_name("buffersink");
  if (!flt_bufsrc || !flt_bufsink) {
    tvherror(LS_TRANSCODE, "%04X: libav default buffers unknown", shortid(t));
    goto out_err;
  }

  memset(opt, 0, sizeof(opt));
  snprintf(opt, sizeof(opt), "video_size=%dx%d:pix_fmt=%d:time_base=%d/%d:pixel_aspect=%d/%d",
		   filter->fctx.i_width,
           filter->fctx.i_height,
           filter->fctx.i_pix_fmt,
           filter->fctx.time_base.num,
           filter->fctx.time_base.den,
           filter->fctx.sample_aspect_ratio.num,
           filter->fctx.sample_aspect_ratio.den);

  err = avfilter_graph_create_filter(&filter->flt_bufsrcctx, flt_bufsrc, "in",
                                     opt, NULL, filter->flt_graph);
  if (err < 0) {
    tvherror(LS_TRANSCODE, "%04X: fltchain IN init error", shortid(t));
    goto out_err;
  }
  else
	  tvhtrace(LS_TRANSCODE, "%04X: Filter: filtchain IN %s", shortid(t), opt);

  err = avfilter_graph_create_filter(&filter->flt_bufsinkctx, flt_bufsink,
                                     "out", NULL, NULL, filter->flt_graph);
  if (err < 0) {
    tvherror(LS_TRANSCODE, "%04X: fltchain OUT init error", shortid(t));
    goto out_err;
  }
  else
	  tvhtrace(LS_TRANSCODE, "%04X: Filter: filtchain IN out", shortid(t));

  pix_fmts[0] = filter->fctx.o_pix_fmt;
  err = av_opt_set_int_list(filter->flt_bufsinkctx, "pix_fmts", pix_fmts,
                            AV_PIX_FMT_NONE, AV_OPT_SEARCH_CHILDREN);
  if (err < 0) {
    tvherror(LS_TRANSCODE, "%08X: fltchain cannot set output pixfmt",
             shortid(t));
    goto out_err;
  }

  flt_outputs->name = av_strdup("in");
  flt_outputs->filter_ctx = filter->flt_bufsrcctx;
  flt_outputs->pad_idx = 0;
  flt_outputs->next = NULL;
  flt_inputs->name = av_strdup("out");
  flt_inputs->filter_ctx = filter->flt_bufsinkctx;
  flt_inputs->pad_idx = 0;
  flt_inputs->next = NULL;

  /* add filters: yadif to deinterlace and a scaler */
  memset(opt, 0, sizeof(opt));
  snprintf(opt, sizeof(opt), "yadif,scale=%dx%d",
		   filter->fctx.o_width,
		   filter->fctx.o_height);
/*  snprintf(opt, sizeof(opt), "w3fdif,scale=%dx%d",
		   filter->fctx.o_width,
		   filter->fctx.o_height);*/
  err = avfilter_graph_parse_ptr(filter->flt_graph,
                                 opt,
                                 &flt_inputs,
                                 &flt_outputs,
                                 NULL);
  if (err < 0) {
    tvherror(LS_TRANSCODE, "%04X: failed to init filter chain", shortid(t));
    goto out_err;
  }

  err = avfilter_graph_config(filter->flt_graph, NULL);
  if (err < 0) {
    tvherror(LS_TRANSCODE, "%04X: failed to config filter chain", shortid(t));
    goto out_err;
  }

  avfilter_inout_free(&flt_inputs);
  avfilter_inout_free(&flt_outputs);

  return 0;  /* all OK */

out_err:
  if (flt_inputs)
    avfilter_inout_free(&flt_inputs);
  if (flt_outputs)
    avfilter_inout_free(&flt_outputs);
  if (filter->flt_graph) {
    avfilter_graph_free(&filter->flt_graph);
    filter->flt_graph = NULL;
  }

  return err;
}

static void
transcoder_filter_stage(struct video_stage *stage)
{
	struct filter  *filter = NULL;
    struct timespec tstart, tend, tdelta;
	int push, pop;
	int ret;
	int got_picture = 0;
    transcoder_stream_t *ts = NULL;
    transcoder_t *t = NULL;

    clock_gettime(CLOCK_MONOTONIC, &tstart);

    ts = (transcoder_stream_t *)stage->vs;
    t = stage->vs->t;
	filter = &stage->stage->filter;

	pop = filter->input_pipeline->pop_pointer;

	if(pop != filter->input_pipeline->push_pointer)
	{
	  tvhtrace(LS_TRANSCODE, "%04X: Filter: Processing input frame %d(ts: %d), pts %" PRIu64 ", dts %" PRIu64 ", duration %" PRIu64 "",
	  	  shortid(t), pop, filter->input_pipeline->stage_timestamp, filter->input_pipeline->vid_frames[pop]->pkt_pts, filter->input_pipeline->vid_frames[pop]->pkt_dts,
		  filter->input_pipeline->vid_frames[pop]->pkt_duration);

	  tvhtrace(LS_TRANSCODE, "%04X:         Input frame %x width %d, height %d", shortid(t), (unsigned int)filter->input_pipeline->vid_frames[pop],
			  filter->input_pipeline->vid_frames[pop]->width, filter->input_pipeline->vid_frames[pop]->height);
	  tvhtrace(LS_TRANSCODE, "%04X:         Input frame format %s", shortid(t),
				  av_get_pix_fmt_name(filter->input_pipeline->vid_frames[pop]->format));

	  filter->input_pipeline->pop_pointer++;

	  if(filter->input_pipeline->pop_pointer >= filter->input_pipeline->pipeline_size)
		  filter->input_pipeline->pop_pointer = 0;

	  if(filter->flt_graph == NULL)
	  {
		  tvhtrace(LS_TRANSCODE, "%04X: Filter: create filter", shortid(t));

		  if(stage->prev == NULL )
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter stage must have a previus stage, found NULL",
	             shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto exit;
		  }

		  if(stage->next == NULL )
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter stage must have a next stage, found NULL",
	             shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto exit;
		  }

		  if(stage->prev->type == TS_DECODER_STAGE)
		  {
			  filter->fctx.i_width = stage->prev->stage->decoder.vid_ictx->width;
			  filter->fctx.i_height = stage->prev->stage->decoder.vid_ictx->height;

			  filter->fctx.sample_aspect_ratio.num = stage->prev->stage->decoder.vid_ictx->sample_aspect_ratio.num;
			  filter->fctx.sample_aspect_ratio.den = stage->prev->stage->decoder.vid_ictx->sample_aspect_ratio.den;
			  filter->fctx.time_base.num = stage->prev->stage->decoder.vid_ictx->time_base.num;
			  filter->fctx.time_base.den = stage->prev->stage->decoder.vid_ictx->time_base.den;
			  filter->fctx.i_pix_fmt = stage->prev->stage->decoder.vid_ictx->pix_fmt;
			  tvhtrace(LS_TRANSCODE, "%04X: Filter: create filter context base on decoder info", shortid(t));
		  }
		  else if(stage->prev->type == TS_FILTER_STAGE)
		  {
			  filter->fctx.i_width = stage->prev->stage->filter.fctx.o_width;
			  filter->fctx.i_height = stage->prev->stage->filter.fctx.o_height;

			  filter->fctx.sample_aspect_ratio.num = stage->prev->stage->filter.fctx.sample_aspect_ratio.num;
			  filter->fctx.sample_aspect_ratio.den = stage->prev->stage->filter.fctx.sample_aspect_ratio.den;
			  filter->fctx.time_base.num = stage->prev->stage->filter.fctx.time_base.num;
			  filter->fctx.time_base.den = stage->prev->stage->filter.fctx.time_base.den;
			  filter->fctx.i_pix_fmt = stage->prev->stage->filter.fctx.o_pix_fmt;
			  tvhtrace(LS_TRANSCODE, "%04X: Filter: create filter context base on filter info", shortid(t));
		  }
		  else
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter previous stage can be decoder or filter, found %d",
	             shortid(t), stage->prev->type);
			  transcoder_stream_invalidate(ts);
			  goto exit;
		  }

		  if(stage->next->type == TS_ENCODER_STAGE)
		  {
			  filter->fctx.o_pix_fmt = stage->next->stage->encoder.vid_octx->pix_fmt;
			  filter->fctx.o_width   = stage->next->stage->encoder.vid_octx->width;
			  filter->fctx.o_height   = stage->next->stage->encoder.vid_octx->height;
			  tvhtrace(LS_TRANSCODE, "%04X:         and encoder info", shortid(t));
		  }
		  else if(stage->prev->type == TS_FILTER_STAGE)
		  {
			  filter->fctx.o_pix_fmt = filter->fctx.i_pix_fmt;
			  filter->fctx.o_width   = filter->fctx.i_width;
			  filter->fctx.o_height  = filter->fctx.i_width;
			  tvhtrace(LS_TRANSCODE, "%04X:         and filter info", shortid(t));
		  }
		  else
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter next stage can be encoder or filter, found %d",
	             shortid(t), stage->next->type);
			  transcoder_stream_invalidate(ts);
			  goto exit;
		  }

		  tvhtrace(LS_TRANSCODE, "%04X:         i_width %d, i_height %d", shortid(t), filter->fctx.i_width, filter->fctx.i_height);
		  tvhtrace(LS_TRANSCODE, "%04X:         o_width %d, o_height %d", shortid(t), filter->fctx.o_width, filter->fctx.o_height);
		  tvhtrace(LS_TRANSCODE, "%04X:         sar.num %d, dar.den %d", shortid(t), filter->fctx.sample_aspect_ratio.num, filter->fctx.sample_aspect_ratio.den);
		  tvhtrace(LS_TRANSCODE, "%04X:         tb.num %d, tb.den %d", shortid(t), filter->fctx.time_base.num, filter->fctx.time_base.den);
		  tvhtrace(LS_TRANSCODE, "%04X:         input pixel format %s", shortid(t), av_get_pix_fmt_name(filter->fctx.i_pix_fmt));
		  tvhtrace(LS_TRANSCODE, "%04X:         output pixel format %s", shortid(t), av_get_pix_fmt_name(filter->fctx.o_pix_fmt));

		  if (create_video_filter(filter, t)) {
			  tvherror(LS_TRANSCODE, "%04X: Video filter creation failed",
	             shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto exit;
		  }
	  }
	  /*
	   * One frame ready in the pipeline, filter it
	   */
	  push = filter->output_pipeline->push_pointer;
	  filter->output_pipeline->vid_frames[push]->pts = filter->input_pipeline->vid_frames[pop]->pts;
	  filter->output_pipeline->vid_frames[push]->pkt_dts = filter->input_pipeline->vid_frames[pop]->pkt_dts;
	  filter->output_pipeline->vid_frames[push]->pkt_pts = filter->input_pipeline->vid_frames[pop]->pkt_pts;
	  filter->output_pipeline->vid_frames[push]->sample_aspect_ratio.num = filter->input_pipeline->vid_frames[pop]->sample_aspect_ratio.num;
	  filter->output_pipeline->vid_frames[push]->sample_aspect_ratio.den = filter->input_pipeline->vid_frames[pop]->sample_aspect_ratio.den;

	  tvhtrace(LS_TRANSCODE, "%04X: Filter: Adding input frame %d %x, pts %" PRIu64 ", dts %" PRIu64 ", duration %" PRIu64 "",
	  	  shortid(t), pop, (unsigned int)filter->input_pipeline->vid_frames[pop], filter->input_pipeline->vid_frames[pop]->pkt_pts, filter->input_pipeline->vid_frames[pop]->pkt_dts,
		  filter->input_pipeline->vid_frames[pop]->pkt_duration);

	  /* push decoded frame into filter chain */
	  if (av_buffersrc_add_frame(filter->flt_bufsrcctx, filter->input_pipeline->vid_frames[pop]) < 0) {
	      tvherror(LS_TRANSCODE, "%04X: filter input error", shortid(t));
	      transcoder_stream_invalidate(ts);
	      goto exit;
	  }

	  /* and pull out a filtered frame */
	  while (1)
	  {
   		  ret = av_buffersink_get_frame(filter->flt_bufsinkctx, filter->output_pipeline->vid_frames[push]);

		  if(ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
		  {
		      av_frame_unref(filter->input_pipeline->vid_frames[pop]);
			  break;
		  }

		  if (ret < 0)
		  {
			  tvherror(LS_TRANSCODE, "%04X: filter output error", shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto exit;
		  }
	      filter->output_pipeline->vid_frames[push]->format  = filter->fctx.o_pix_fmt;
	      filter->output_pipeline->vid_frames[push]->width   = filter->fctx.o_width;
	      filter->output_pipeline->vid_frames[push]->height  = filter->fctx.o_height;
	      filter->output_pipeline->vid_frames[push]->pkt_dts = filter->input_pipeline->vid_frames[pop]->pkt_dts;
          filter->output_pipeline->vid_frames[push]->pkt_pts = filter->input_pipeline->vid_frames[pop]->pkt_pts;

	  	  if (filter->input_pipeline->vid_frames[pop]->reordered_opaque != AV_NOPTS_VALUE)
	    	  filter->output_pipeline->vid_frames[push]->pts = filter->input_pipeline->vid_frames[pop]->reordered_opaque;
	      else if (stage->prev->type == TS_DECODER_STAGE && stage->prev->stage->decoder.vid_ictx->coded_frame &&
			       stage->prev->stage->decoder.vid_ictx->coded_frame->pts != AV_NOPTS_VALUE)
		  	  filter->output_pipeline->vid_frames[push]->pts = filter->input_pipeline->vid_frames[pop]->pts;

    	  tvhtrace(LS_TRANSCODE, "%04X: Filter: available output frame %d (ts: %d), pts %" PRIu64 ", pkt_pts %" PRIu64 ", pkt_dts %" PRIu64 "",
    			   shortid(t), push, filter->output_pipeline->stage_timestamp, filter->output_pipeline->vid_frames[push]->pts,
				   filter->output_pipeline->vid_frames[push]->pkt_pts, filter->output_pipeline->vid_frames[push]->pkt_dts);

	  	  tvhtrace(LS_TRANSCODE, "%04X:         Output frame %x width %d, height %d", shortid(t), (unsigned int)filter->output_pipeline->vid_frames[push],
	  			  filter->output_pipeline->vid_frames[push]->width, filter->output_pipeline->vid_frames[push]->height);
	  	  tvhtrace(LS_TRANSCODE, "%04X:         Output frame format %s", shortid(t),
	  			  av_get_pix_fmt_name(filter->output_pipeline->vid_frames[push]->format));

	      av_frame_unref(filter->input_pipeline->vid_frames[pop]);

	  	  filter->output_pipeline->push_pointer++;

	  	  if(filter->output_pipeline->push_pointer >= filter->output_pipeline->pipeline_size)
	  		  filter->output_pipeline->push_pointer = 0;

	  	  got_picture = 1;
	  }
	}
	else
	   tvhtrace(LS_TRANSCODE, "%04X: Filter: no available input buffer", shortid(t));

exit:
  clock_gettime(CLOCK_MONOTONIC, &tend);

  tdelta = timeDiff(tstart, tend);

  if(got_picture)
  {
	  tvhtrace(LS_TRANSCODE, "%04X: Filter: took %dsec and %dns and frame available",
			   shortid(t), (int)tdelta.tv_sec, (int)tdelta.tv_nsec);
  }
}

static void
transcoder_encoder_stage(struct video_stage *stage)
{
    AVCodec *ocodec;
	AVCodecContext *octx;
	AVDictionary *opts = NULL;
	struct encoder *encoder = NULL;
    struct timespec tstart, tend, tdelta;
	int pop;
	int ret, got_output;
    transcoder_stream_t *ts = NULL;
    transcoder_t *t = NULL;
    static int max_bitrate = INT_MAX / ((3000*10)/8);

    clock_gettime(CLOCK_MONOTONIC, &tstart);

    ts = (transcoder_stream_t *)stage->vs;
    t = stage->vs->t;

	encoder = &stage->stage->encoder;
    ocodec = stage->stage->encoder.vid_ocodec;

	got_output = 0;

	av_init_packet(&encoder->packet);
	encoder->packet.data = NULL;
	encoder->packet.size = 0;

	octx = encoder->vid_octx;

	pop = encoder->input_pipeline->pop_pointer;
	if(pop != encoder->input_pipeline->push_pointer)
	{
	    if(!avcodec_is_open(octx))
	    {
	        // set default gop size to 1 second
	  	  octx->gop_size        = ceil(av_q2d(av_inv_q(av_div_q(octx->time_base, (AVRational){1, octx->ticks_per_frame}))));

	  	  switch (ts->ts_type)
  		  {
	  		  case SCT_MPEG2VIDEO:
	  			  octx->flags         |= CODEC_FLAG_GLOBAL_HEADER;

	  			  if (t->t_props.tp_vbitrate < 64) {
	  				  // encode with specified quality and optimize for low latency
	  				  // valid values for quality are 2-31, smaller means better quality, use 5 as default
	  				  octx->flags          |= CODEC_FLAG_QSCALE;
	  				  octx->global_quality  = FF_QP2LAMBDA *
	  						  (t->t_props.tp_vbitrate == 0 ? 5 : MINMAX(t->t_props.tp_vbitrate, 2, 31));
	  			  }
	  			  else
	  			  {
	  				  // encode with specified bitrate and optimize for high compression
	  				  octx->bit_rate        = t->t_props.tp_vbitrate * 1000;
	  				  octx->rc_max_rate     = ceil(octx->bit_rate * 1.25);
	  				  octx->rc_buffer_size  = octx->rc_max_rate * 3;
	  				  // use gop size of 5 seconds
	  				  octx->gop_size       *= 5;
	  				  // activate b-frames
	  				  octx->max_b_frames    = 3;
	  			  }

	  	      break;

	  		  case SCT_VP8:
	  			  // setting quality to realtime will use as much CPU for transcoding as possible,
	  			  // while still encoding in realtime
	  			  av_dict_set(&opts, "quality", "realtime", 0);

	  			  if (t->t_props.tp_vbitrate < 64) {
	  				  // encode with specified quality and optimize for low latency
	  				  // valid values for quality are 1-63, smaller means better quality, use 15 as default
	  				  av_dict_set_int__(&opts,      "crf", t->t_props.tp_vbitrate == 0 ? 15 : t->t_props.tp_vbitrate, 0);
	  				  // bitrate setting is still required, as it's used as max rate in CQ mode
	  				  // and set to a very low value by default
	  				  octx->bit_rate        = 25000000;
	  			  }
	  			  else
	  			  {
	  				  // encode with specified bitrate and optimize for high compression
	  				  octx->bit_rate        = t->t_props.tp_vbitrate * 1000;
	  				  octx->rc_buffer_size  = octx->bit_rate * 3;
	  				  // use gop size of 5 seconds
	  				  octx->gop_size       *= 5;
	  			  }
	  	      break;

	  		  case SCT_H264:
	  			  octx->flags         |= CODEC_FLAG_GLOBAL_HEADER;

	  			  // Default = "medium". We gain more encoding speed compared to the loss of quality when lowering it _slightly_.
	  			  // select preset according to system performance and codec type
	  			  av_dict_set(&opts, "preset",  t->t_props.tp_vcodec_preset, 0);
	  			  tvhinfo(LS_TRANSCODE, "%04X: Using preset %s", shortid(t), t->t_props.tp_vcodec_preset);

	  			  // All modern devices should support "high" profile
	  			  if(strcmp(ocodec->name, "h264_omx") != 0)
	  				  av_dict_set(&opts, "profile", "high", 0);

	  			  if (t->t_props.tp_vbitrate < 64) {
	  				  // encode with specified quality and optimize for low latency
	  				  // valid values for quality are 1-51, smaller means better quality, use 15 as default
	  				  av_dict_set_int__(&opts,      "crf", t->t_props.tp_vbitrate == 0 ? 15 : MIN(51, t->t_props.tp_vbitrate), 0);
	  				  // tune "zerolatency" removes as much encoder latency as possible
	  				  av_dict_set(&opts,      "tune", "zerolatency", 0);
	  			  }
	  			  else
	  			  {
	  				  // encode with specified bitrate and optimize for high compression
	  				  octx->bit_rate        = t->t_props.tp_vbitrate * 1000;
	  				  octx->rc_max_rate     = ceil(octx->bit_rate * 1.25);
	  				  octx->rc_buffer_size  = octx->rc_max_rate * 3;
	  				  // force-cfr=1 is needed for correct bitrate calculation (tune "zerolatency" also sets this)
	  				  av_dict_set(&opts,      "x264opts", "force-cfr=1", 0);
	  				  // use gop size of 5 seconds
	  				  octx->gop_size       *= 5;
	  			  }
	  	      break;

	  		  case SCT_HEVC:
	  			  // on all hardware ultrafast (or maybe superfast) should be safe
	  			  // select preset according to system performance
	  			  av_dict_set(&opts, "preset",  t->t_props.tp_vcodec_preset, 0);
	  			  tvhinfo(LS_TRANSCODE, "%04X: Using preset %s", shortid(t), t->t_props.tp_vcodec_preset);

	  			  // disables encoder features which tend to be bottlenecks for the decoder/player
	  			  av_dict_set(&opts, "tune",   "fastdecode", 0);

	  			  if (t->t_props.tp_vbitrate < 64) {
	  				  // encode with specified quality
	  				  // valid values for crf are 1-51, smaller means better quality
	  				  // use 18 as default
	  				  av_dict_set_int__(&opts, "crf", t->t_props.tp_vbitrate == 0 ? 18 : MIN(51, t->t_props.tp_vbitrate), 0);

	  				  // the following is equivalent to tune=zerolatency for presets: ultra/superfast
	  				  av_dict_set(&opts, "x265-params", "bframes=0",        0);
	  				  av_dict_set(&opts, "x265-params", ":rc-lookahead=0",  AV_DICT_APPEND);
	  				  av_dict_set(&opts, "x265-params", ":scenecut=0",      AV_DICT_APPEND);
	  				  av_dict_set(&opts, "x265-params", ":frame-threads=1", AV_DICT_APPEND);
	  			  }
	  			  else
	  			  {
	  				  int bitrate, maxrate, bufsize;
	  				  bitrate = (t->t_props.tp_vbitrate > max_bitrate) ? max_bitrate : t->t_props.tp_vbitrate;
	  				  maxrate = ceil(bitrate * 1.25);
	  				  bufsize = maxrate * 3;

	  				  tvhdebug(LS_TRANSCODE, "tuning HEVC encoder for ABR rate control, "
	  						  "bitrate: %dkbps, vbv-bufsize: %dkbits, vbv-maxrate: %dkbps",
	  						  bitrate, bufsize, maxrate);

	  				  // this is the same as setting --bitrate=bitrate
	  				  octx->bit_rate = bitrate * 1000;

	  				  av_dict_set(&opts,       "x265-params", "vbv-bufsize=",  0);
	  				  av_dict_set_int__(&opts, "x265-params", bufsize,         AV_DICT_APPEND);
	  				  av_dict_set(&opts,       "x265-params", ":vbv-maxrate=", AV_DICT_APPEND);
	  				  av_dict_set_int__(&opts, "x265-params", maxrate,         AV_DICT_APPEND);
	  				  av_dict_set(&opts,       "x265-params", ":strict-cbr=1", AV_DICT_APPEND);
	  			  }
	  			  // reduce key frame interface for live streaming
	  			  av_dict_set(&opts, "x265-params", ":keyint=49:min-keyint=15", AV_DICT_APPEND);
	  	      break;

	  		  default:
	  	      break;
	  		  }

	  		  if (avcodec_open2(octx, ocodec, &opts) < 0)
	  		  {
	  			  tvherror(LS_TRANSCODE, "%04X: Unable to open %s encoder",
	  	               shortid(t), ocodec->name);
	  			  transcoder_stream_invalidate(ts);
	  			  goto cleanup;
	  		  }
	  	  }
		  /*
	 	   * One frame available out from the filter chain, encode it
		   */
	  	  tvhtrace(LS_TRANSCODE, "%04X: Encoder: Processing input frame %d(ts: %d), pts %" PRIu64 ", dts %" PRIu64 ", duration %" PRIu64 "",
	  			  shortid(t), pop, encoder->input_pipeline->stage_timestamp, encoder->input_pipeline->vid_frames[pop]->pkt_pts, encoder->input_pipeline->vid_frames[pop]->pkt_dts,
				  encoder->input_pipeline->vid_frames[pop]->pkt_duration);

		  tvhtrace(LS_TRANSCODE, "%04X:          Input frame %x width %d, height %d", shortid(t), (unsigned int)encoder->input_pipeline->vid_frames[pop],
				  encoder->input_pipeline->vid_frames[pop]->width, encoder->input_pipeline->vid_frames[pop]->height);
		  tvhtrace(LS_TRANSCODE, "%04X:          Input frame format %s", shortid(t),
				  av_get_pix_fmt_name(encoder->input_pipeline->vid_frames[pop]->format));

		  ret = avcodec_encode_video2(octx, &encoder->packet, encoder->input_pipeline->vid_frames[pop], &got_output);
		  if (ret < 0) {
			  tvherror(LS_TRANSCODE, "%04X: Error encoding frame", shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }

		  av_frame_unref(encoder->input_pipeline->vid_frames[pop]);

		  encoder->input_pipeline->pop_pointer++;

		  if(encoder->input_pipeline->pop_pointer >= encoder->input_pipeline->pipeline_size)
			  encoder->input_pipeline->pop_pointer = 0;

	}
	else
	    tvhtrace(LS_TRANSCODE, "%04X: Encoder: no available input buffer", shortid(t));

	if (got_output)
	{
		tvhtrace(LS_TRANSCODE, "%04X: Encoder: Encoded packet pts %" PRIu64 ", dts %" PRIu64 "\n", shortid(t), encoder->packet.pts, encoder->packet.dts);
		send_video_packet(t, ts, encoder, &encoder->packet, octx);
	}
cleanup:

    if(encoder)
    	av_free_packet(&encoder->packet);

    if(opts)
	    av_dict_free(&opts);

    clock_gettime(CLOCK_MONOTONIC, &tend);

    tdelta = timeDiff(tstart, tend);

    if(got_output)
    {
  	  tvhtrace(LS_TRANSCODE, "%04X: Encoder: took %dsec and %dns and packet available",
  			   shortid(t), (int)tdelta.tv_sec, (int)tdelta.tv_nsec);
    }
    else
    {
  	  tvhtrace(LS_TRANSCODE, "%04X: Encoder: took %dsec and %dns and NO packet available",
  			   shortid(t), (int)tdelta.tv_sec, (int)tdelta.tv_nsec);
    }

}


static void *transcoder_stage_thread(void *arg)
{
	struct video_stage *stage = (struct video_stage *)arg;
	video_stream_t *vs = stage->vs;
	transcoder_t *t = vs->t;

	int running = 1;

	tvhtrace(LS_TRANSCODE, "%04X: Stage %d started", shortid(t), stage->this_stage_number);
	while(running)
	{
		pthread_mutex_lock(stage->condition_mutex);
		while(!(vs->stage_run_mask & (1 << stage->this_stage_number)))
		{
			pthread_mutex_unlock(stage->condition_mutex);
			pthread_cond_wait(stage->condition_sync, stage->condition_mutex);
		}

		if(vs->stage_run_mask & (1 << (stage->this_stage_number+EXIT_STAGE_CONDITION_SHIFT)))
		{
       	    tvhtrace(LS_TRANSCODE, "%04X: Stage %d scheduled for exit", shortid(t), stage->this_stage_number);
			running = 0;
			pthread_mutex_unlock(stage->condition_mutex);
			continue;
		}

		//Clean event
		vs->stage_run_mask &= ~(1 << stage->this_stage_number);
		pthread_mutex_unlock(stage->condition_mutex);

		/*if(stage->type == TS_DECODER_STAGE)
			transcoder_decoder_stage(stage);
		else */if(stage->type == TS_FILTER_STAGE)
			transcoder_filter_stage(stage);
		else if(stage->type == TS_ENCODER_STAGE)
			transcoder_encoder_stage(stage);
		else
       	    tvherror(LS_TRANSCODE, "%04X: Stage %d type %d unsupported", shortid(t), stage->this_stage_number, stage->type);

	}

	tvhtrace(LS_TRANSCODE, "%04X: Stage %d exiting...", shortid(t), stage->this_stage_number);
	return NULL;
}

/**
 *
 */
static void
transcoder_stream_video(transcoder_t *t, transcoder_stream_t *ts, th_pkt_t *pkt)
{
  AVCodec *icodec, *ocodec;
  AVCodecContext *ictx;
  AVDictionary *opts;
  struct video_stage *videostage;
  struct decoder *decoder = NULL;
  struct encoder *encoder = NULL;
#if OLD_FILTER
  struct filter  *filter = NULL;
#endif
#if OLD_ENCODER
  AVCodecContext *octx;
  static int max_bitrate = INT_MAX / ((3000*10)/8);
  int got_output = 0, ret;
  int pop;
  AVFrame *iframe;
  avframes_pipeline_t *ipipeline;
#endif
  struct timespec tstart, tend, tdelta;

  AVFrame *oframe;
  avframes_pipeline_t *opipeline;
  int push;
  int length, got_picture = 0;
  video_stream_t *vs = (video_stream_t*)ts;
  streaming_message_t *sm;
  th_pkt_t *pkt2;
  static int stage_timestamp = 0;
  /*
   * Encoder (last stage) pixel format is required to build the filter chain
   * So it must be initialized before starting the transcoding queue
   */
  clock_gettime(CLOCK_MONOTONIC, &tstart);

  ocodec = vs->video_stages[vs->ts_stages-1].stage->encoder.vid_ocodec;

  switch (ts->ts_type)
  {
  case SCT_MPEG2VIDEO:
     if (!strcmp(ocodec->name, "nvenc") || !strcmp(ocodec->name, "mpeg2_qsv"))
    	 vs->video_stages[vs->ts_stages-1].stage->encoder.vid_octx->pix_fmt    = AV_PIX_FMT_NV12;
     else
    	 vs->video_stages[vs->ts_stages-1].stage->encoder.vid_octx    = AV_PIX_FMT_YUV420P;
  break;

  case SCT_VP8:
	  vs->video_stages[vs->ts_stages-1].stage->encoder.vid_octx->pix_fmt        = AV_PIX_FMT_YUV420P;
  break;

  case SCT_H264:
     if (!strcmp(ocodec->name, "nvenc") || !strcmp(ocodec->name, "h264_qsv"))
    	 vs->video_stages[vs->ts_stages-1].stage->encoder.vid_octx->pix_fmt    = AV_PIX_FMT_NV12;
     else
    	 vs->video_stages[vs->ts_stages-1].stage->encoder.vid_octx->pix_fmt    = AV_PIX_FMT_YUV420P;
  break;

  case SCT_HEVC:
	  vs->video_stages[vs->ts_stages-1].stage->encoder.vid_octx->pix_fmt        = AV_PIX_FMT_YUV420P;
  break;

  default:
  break;
  }

  icodec = vs->video_stages[0].stage->decoder.vid_icodec;

  opts = NULL;

  /*
   * Get decoder handler and decode, this will become the decoder
   * videostage task body
   */
  videostage = &vs->video_stages[0];
  decoder = &videostage->stage->decoder;

  ictx = decoder->vid_ictx;

  if (!avcodec_is_open(ictx)) {
	  ictx->width = 720;
	  ictx->height = 576;
      ictx->framerate.num = 1;
      ictx->framerate.den = 25;

    if (icodec->id == AV_CODEC_ID_H264) {
      if (ts->ts_input_gh) {
        ictx->extradata_size = pktbuf_len(ts->ts_input_gh);
        ictx->extradata = av_malloc(ictx->extradata_size);
        memcpy(ictx->extradata,
               pktbuf_ptr(ts->ts_input_gh), pktbuf_len(ts->ts_input_gh));
        tvhtrace(LS_TRANSCODE, "%04X: copy meta data for H264 (len %zd)",
                 shortid(t), pktbuf_len(ts->ts_input_gh));
      }
    }

    if (avcodec_open2(ictx, icodec, NULL) < 0) {
      tvherror(LS_TRANSCODE, "%04X: Unable to open %s decoder", shortid(t), icodec->name);
      transcoder_stream_invalidate(ts);
      goto cleanup;
    }
  }

  if (!vs->vid_first_sent) {
    /* notify global headers that we're live */
    /* the video packets might be delayed */
    pkt2 = pkt_alloc(NULL, 0, pkt->pkt_pts, pkt->pkt_dts);
    pkt2->pkt_componentindex = pkt->pkt_componentindex;
    sm = streaming_msg_create_pkt(pkt2);
    streaming_target_deliver2(ts->ts_target, sm);
    pkt_ref_dec(pkt2);
    vs->vid_first_sent = 1;
  }

  av_init_packet(&decoder->packet);

  decoder->packet.data     = pktbuf_ptr(pkt->pkt_payload);
  decoder->packet.size     = pktbuf_len(pkt->pkt_payload);
  decoder->packet.pts      = pkt->pkt_pts;
  decoder->packet.dts      = pkt->pkt_dts;
  decoder->packet.duration = pkt->pkt_duration;

  tvhtrace(LS_TRANSCODE, "%04X: Decoder: Processing input packet %d, pts %" PRIu64 ", dts %" PRIu64 ", duration %d",
		  shortid(t), stage_timestamp, pkt->pkt_pts, pkt->pkt_dts, pkt->pkt_duration);

  opipeline = decoder->output_pipeline;
  push = opipeline->push_pointer;
  oframe = decoder->output_pipeline->vid_frames[push];

  oframe->pts = decoder->packet.pts;
  oframe->pkt_dts = decoder->packet.dts;
  oframe->pkt_pts = decoder->packet.pts;
  opipeline->stage_timestamp = stage_timestamp;
  ictx->reordered_opaque = decoder->packet.pts;
#if 1

  length = avcodec_decode_video2(ictx, decoder->output_pipeline->vid_frames[push], &got_picture, &decoder->packet);
  if (length <= 0) {
    if (length == AVERROR_INVALIDDATA) goto cleanup;
    tvherror(LS_TRANSCODE, "%04X: Unable to decode video (%d, %s)",
             shortid(t), length, get_error_text(length));
    goto cleanup;
  }
#else
  length = avcodec_send_packet(ictx, &decoder->packet);
  // In particular, we don't expect AVERROR(EAGAIN), because we read all
  // decoded frames with avcodec_receive_frame() until done.
  if (length < 0 && length != AVERROR_EOF)
  {
	  got_picture = -1;
	  goto cleanup;
  }

  length = avcodec_receive_frame(ictx, oframe);
  if (length < 0 && length != AVERROR(EAGAIN))
  {
	  got_picture = -2;
	  goto cleanup;
  }
  else if(length == AVERROR(EAGAIN))
      got_picture = -3;
  else if (length > 0)
	  got_picture = 1;

#endif
  clock_gettime(CLOCK_MONOTONIC, &tend);
  tdelta = timeDiff(tstart, tend);

  if (got_picture != 1)
  {
	  goto cleanup;
  }
  else
  {


	  tvhtrace(LS_TRANSCODE, "%04X: Decoder: available output frame %d(ts %d, length %d), pts %" PRIu64 ", pkt_pts %" PRIu64 ", pkt_dts %" PRIu64 "",
			   shortid(t), push, opipeline->stage_timestamp, length, oframe->pts, oframe->pkt_pts, oframe->pkt_dts);
  	  tvhtrace(LS_TRANSCODE, "%04X: Decoder: took %dsec and %dns and frame available, length %d",
  			   shortid(t), (int)tdelta.tv_sec, (int)tdelta.tv_nsec, length);

	  /*
	   * Fix DTS
	   */
	  //oframe->pkt_dts = oframe->pkt_pts;
	  decoder->output_pipeline->push_pointer++;


	  if(decoder->output_pipeline->push_pointer >= decoder->output_pipeline->pipeline_size)
		  decoder->output_pipeline->push_pointer = 0;

	  /*
	   * Got a picture, set the encoder (last stage) context based on the first decoded picture
	   * context
	   */
	  encoder = &vs->video_stages[vs->ts_stages-1].stage->encoder;

	  encoder->vid_octx->sample_aspect_ratio.num = ictx->sample_aspect_ratio.num;
	  encoder->vid_octx->sample_aspect_ratio.den = ictx->sample_aspect_ratio.den;

	  encoder->vid_octx->width           = vs->vid_width  ? vs->vid_width  : ictx->width;
	  encoder->vid_octx->height          = vs->vid_height ? vs->vid_height : ictx->height;

      encoder->pkt_duration = pkt->pkt_duration;
      encoder->pkt_commercial = pkt->pkt_commercial;
      encoder->pkt_componentindex = pkt->pkt_componentindex;
      encoder->pkt_field = pkt->pkt_field;
      encoder->pkt_aspect_num = pkt->pkt_aspect_num;
      encoder->pkt_aspect_den = pkt->pkt_aspect_den;
	  // Encoder uses "time_base" for bitrate calculation, but "time_base" from decoder
	  // will be deprecated in the future, therefore calculate "time_base" from "framerate" if available.
	  encoder->vid_octx->ticks_per_frame = ictx->ticks_per_frame;
	  if (ictx->framerate.num == 0) {
	      ictx->framerate.num = 30;
	      ictx->framerate.den = 1;
	  }
	  if (ictx->time_base.num == 0) {
	    ictx->time_base.num = ictx->framerate.den;
	    ictx->time_base.den = ictx->framerate.num;
	  }
	  encoder->vid_octx->framerate = ictx->framerate;
	#if LIBAVCODEC_VERSION_MICRO >= 100 && LIBAVCODEC_VERSION_INT >= AV_VERSION_INT(56, 13, 100) // ffmpeg 2.5
	  encoder->vid_octx->time_base       = av_inv_q(av_mul_q(ictx->framerate, av_make_q(ictx->ticks_per_frame, 1)));
	#else
	  encoder->vid_octx->time_base       = ictx->time_base;
	#endif
  }
  /*
   * Get filter handler and filter, this will become the decoder
   * videostage task body
   */

  encoder = NULL;
#if OLD_FILTER
  videostage = &vs->video_stages[1];
  filter = &videostage->stage->filter;

  pop = filter->input_pipeline->pop_pointer;
  ipipeline = filter->input_pipeline;

  if(pop != filter->input_pipeline->push_pointer)
  {
	  iframe = filter->input_pipeline->vid_frames[pop];

	  tvhtrace(LS_TRANSCODE, "%04X: Filter: Processing input frame %d(ts %d), pts %" PRIu64 ", pkt_pts %" PRIu64 ", pkt_dts %" PRIu64 ", duration %" PRIu64 "",
	  	  shortid(t), pop, ipipeline->stage_timestamp, iframe->pts, iframe->pkt_pts, iframe->pkt_dts, iframe->pkt_duration);

	  tvhtrace(LS_TRANSCODE, "%04X:         Input frame %x width %d, height %d", shortid(t), (unsigned int)iframe,
			  iframe->width, iframe->height);
	  tvhtrace(LS_TRANSCODE, "%04X:         Input frame format %s", shortid(t),
				  av_get_pix_fmt_name(iframe->format));

	  filter->input_pipeline->pop_pointer++;

	  if(filter->input_pipeline->pop_pointer >= filter->input_pipeline->pipeline_size)
		  filter->input_pipeline->pop_pointer = 0;

	  if(filter->flt_graph == NULL)
	  {
		  tvhtrace(LS_TRANSCODE, "%04X: Filter: create filter", shortid(t));

		  if(videostage->prev == NULL )
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter videostage must have a previus videostage, found NULL",
	             shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }

		  if(videostage->next == NULL )
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter videostage must have a next videostage, found NULL",
	             shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }

		  if(videostage->prev->type == TS_DECODER_STAGE)
		  {
			  filter->fctx.i_width = videostage->prev->stage->decoder.vid_ictx->width;
			  filter->fctx.i_height = videostage->prev->stage->decoder.vid_ictx->height;

			  filter->fctx.sample_aspect_ratio.num = videostage->prev->stage->decoder.vid_ictx->sample_aspect_ratio.num;
			  filter->fctx.sample_aspect_ratio.den = videostage->prev->stage->decoder.vid_ictx->sample_aspect_ratio.den;
			  filter->fctx.time_base.num = videostage->prev->stage->decoder.vid_ictx->time_base.num;
			  filter->fctx.time_base.den = videostage->prev->stage->decoder.vid_ictx->time_base.den;
			  filter->fctx.i_pix_fmt = videostage->prev->stage->decoder.vid_ictx->pix_fmt;
			  tvhtrace(LS_TRANSCODE, "%04X: Filter: create filter context base on decoder info", shortid(t));
		  }
		  else if(videostage->prev->type == TS_FILTER_STAGE)
		  {
			  filter->fctx.i_width = videostage->prev->stage->filter.fctx.o_width;
			  filter->fctx.i_height = videostage->prev->stage->filter.fctx.o_height;

			  filter->fctx.sample_aspect_ratio.num = videostage->prev->stage->filter.fctx.sample_aspect_ratio.num;
			  filter->fctx.sample_aspect_ratio.den = videostage->prev->stage->filter.fctx.sample_aspect_ratio.den;
			  filter->fctx.time_base.num = videostage->prev->stage->filter.fctx.time_base.num;
			  filter->fctx.time_base.den = videostage->prev->stage->filter.fctx.time_base.den;
			  filter->fctx.i_pix_fmt = videostage->prev->stage->filter.fctx.o_pix_fmt;
			  tvhtrace(LS_TRANSCODE, "%04X: Filter: create filter context base on filter info", shortid(t));
		  }
		  else
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter previous videostage can be decoder or filter, found %d",
	             shortid(t), videostage->prev->type);
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }

		  if(videostage->next->type == TS_ENCODER_STAGE)
		  {
			  filter->fctx.o_pix_fmt = videostage->next->stage->encoder.vid_octx->pix_fmt;
			  filter->fctx.o_width   = videostage->next->stage->encoder.vid_octx->width;
			  filter->fctx.o_height   = videostage->next->stage->encoder.vid_octx->height;
			  tvhtrace(LS_TRANSCODE, "%04X:         and encoder info", shortid(t));
		  }
		  else if(videostage->prev->type == TS_FILTER_STAGE)
		  {
			  filter->fctx.o_pix_fmt = filter->fctx.i_pix_fmt;
			  filter->fctx.o_width   = filter->fctx.i_width;
			  filter->fctx.o_height  = filter->fctx.i_width;
			  tvhtrace(LS_TRANSCODE, "%04X:         and filter info", shortid(t));
		  }
		  else
		  {
			  tvherror(LS_TRANSCODE, "%04X: Video filter next videostage can be encoder or filter, found %d",
	             shortid(t), videostage->next->type);
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }

		  tvhtrace(LS_TRANSCODE, "%04X:         i_width %d, i_height %d", shortid(t), filter->fctx.i_width, filter->fctx.i_height);
		  tvhtrace(LS_TRANSCODE, "%04X:         o_width %d, o_height %d", shortid(t), filter->fctx.o_width, filter->fctx.o_height);
		  tvhtrace(LS_TRANSCODE, "%04X:         sar.num %d, dar.den %d", shortid(t), filter->fctx.sample_aspect_ratio.num, filter->fctx.sample_aspect_ratio.den);
		  tvhtrace(LS_TRANSCODE, "%04X:         tb.num %d, tb.den %d", shortid(t), filter->fctx.time_base.num, filter->fctx.time_base.den);
		  tvhtrace(LS_TRANSCODE, "%04X:         input pixel format %s", shortid(t), av_get_pix_fmt_name(filter->fctx.i_pix_fmt));
		  tvhtrace(LS_TRANSCODE, "%04X:         output pixel format %s", shortid(t), av_get_pix_fmt_name(filter->fctx.o_pix_fmt));

		  if (create_video_filter(filter, t)) {
			  tvherror(LS_TRANSCODE, "%04X: Video filter creation failed",
	             shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }
	  }
	  /*
	   * One frame ready in the pipeline, filter it
	   */
	  push = filter->output_pipeline->push_pointer;
	  oframe = filter->output_pipeline->vid_frames[push];
	  opipeline = filter->output_pipeline;
	  opipeline->stage_timestamp = ipipeline->stage_timestamp;
	  oframe->pts                     = iframe->pts;
	  oframe->pkt_dts                 = iframe->pkt_dts;
	  oframe->pkt_pts                 = iframe->pkt_pts;
	  oframe->sample_aspect_ratio.num = iframe->sample_aspect_ratio.num;
	  oframe->sample_aspect_ratio.den = iframe->sample_aspect_ratio.den;


	  /* push decoded frame into filter chain */
	  if (av_buffersrc_add_frame(filter->flt_bufsrcctx, filter->input_pipeline->vid_frames[pop]) < 0) {
	      tvherror(LS_TRANSCODE, "%04X: filter input error", shortid(t));
	      transcoder_stream_invalidate(ts);
	      goto cleanup;
	  }

	  /* and pull out a filtered frame */
	  while (1)
	  {
  		  ret = av_buffersink_get_frame(filter->flt_bufsinkctx, filter->output_pipeline->vid_frames[push]);

  		  if (ret == AVERROR(EAGAIN) || ret == AVERROR_EOF)
			break;

  		  if (ret < 0)
  		  {
			  tvherror(LS_TRANSCODE, "%04X: filter output error", shortid(t));
			  transcoder_stream_invalidate(ts);
			  goto cleanup;
		  }

	      filter->output_pipeline->vid_frames[push]->format  = filter->fctx.o_pix_fmt;
	      filter->output_pipeline->vid_frames[push]->width   = filter->fctx.o_width;
	      filter->output_pipeline->vid_frames[push]->height  = filter->fctx.o_height;
	      filter->output_pipeline->vid_frames[push]->pkt_dts = filter->input_pipeline->vid_frames[pop]->pkt_dts;
          filter->output_pipeline->vid_frames[push]->pkt_pts = filter->input_pipeline->vid_frames[pop]->pkt_pts;

    	  if (filter->input_pipeline->vid_frames[pop]->reordered_opaque != AV_NOPTS_VALUE)
	    	  filter->output_pipeline->vid_frames[push]->pts = filter->input_pipeline->vid_frames[pop]->reordered_opaque;
	      else if (videostage->prev->type == TS_DECODER_STAGE && videostage->prev->stage->decoder.vid_ictx->coded_frame &&
			       videostage->prev->stage->decoder.vid_ictx->coded_frame->pts != AV_NOPTS_VALUE)
		  	  filter->output_pipeline->vid_frames[push]->pts = filter->input_pipeline->vid_frames[pop]->pts;

    	  tvhtrace(LS_TRANSCODE, "%04X: Filter: available output frame %d(ts %d), pts %" PRIu64 ", pkt_pts %" PRIu64 ", pkt_dts %" PRIu64 "",
    			   shortid(t), push, opipeline->stage_timestamp, oframe->pts, oframe->pkt_pts, oframe->pkt_dts);

    	  tvhtrace(LS_TRANSCODE, "%04X:         Output frame %x width %d, height %d", shortid(t), (unsigned int)oframe,
    			  oframe->width, oframe->height);
    	  tvhtrace(LS_TRANSCODE, "%04X:         Output frame format %s", shortid(t),
    			  av_get_pix_fmt_name(oframe->format));


          av_frame_unref(iframe);

    	  filter->output_pipeline->push_pointer++;

    	  if(filter->output_pipeline->push_pointer >= filter->output_pipeline->pipeline_size)
    		  filter->output_pipeline->push_pointer = 0;

	  }
  }
  else
	  tvhtrace(LS_TRANSCODE, "%04X: Filter: no available input buffer", shortid(t));
#else
#if !USE_THREADING
  transcoder_filter_stage(&vs->video_stages[1]);
#endif
#endif

#if OLD_ENCODER
  videostage = &vs->video_stages[2];
  encoder = &videostage->stage->encoder;
  got_output = 0;

  av_init_packet(&encoder->packet);
  encoder->packet.data = NULL;
  encoder->packet.size = 0;

  octx = encoder->vid_octx;

  if(!avcodec_is_open(octx))
  {
      // set default gop size to 1 second
	  octx->gop_size        = ceil(av_q2d(av_inv_q(av_div_q(octx->time_base, (AVRational){1, octx->ticks_per_frame}))));

	  switch (ts->ts_type)
	  {
	  case SCT_MPEG2VIDEO:
		  octx->flags         |= CODEC_FLAG_GLOBAL_HEADER;

		  if (t->t_props.tp_vbitrate < 64) {
			  // encode with specified quality and optimize for low latency
			  // valid values for quality are 2-31, smaller means better quality, use 5 as default
			  octx->flags          |= CODEC_FLAG_QSCALE;
			  octx->global_quality  = FF_QP2LAMBDA *
					  (t->t_props.tp_vbitrate == 0 ? 5 : MINMAX(t->t_props.tp_vbitrate, 2, 31));
		  }
		  else
		  {
			  // encode with specified bitrate and optimize for high compression
			  octx->bit_rate        = t->t_props.tp_vbitrate * 1000;
			  octx->rc_max_rate     = ceil(octx->bit_rate * 1.25);
			  octx->rc_buffer_size  = octx->rc_max_rate * 3;
			  // use gop size of 5 seconds
			  octx->gop_size       *= 5;
			  // activate b-frames
			  octx->max_b_frames    = 3;
		  }

      break;

	  case SCT_VP8:
		  // setting quality to realtime will use as much CPU for transcoding as possible,
		  // while still encoding in realtime
		  av_dict_set(&opts, "quality", "realtime", 0);

		  if (t->t_props.tp_vbitrate < 64) {
			  // encode with specified quality and optimize for low latency
			  // valid values for quality are 1-63, smaller means better quality, use 15 as default
			  av_dict_set_int__(&opts,      "crf", t->t_props.tp_vbitrate == 0 ? 15 : t->t_props.tp_vbitrate, 0);
			  // bitrate setting is still required, as it's used as max rate in CQ mode
			  // and set to a very low value by default
			  octx->bit_rate        = 25000000;
		  }
		  else
		  {
			  // encode with specified bitrate and optimize for high compression
			  octx->bit_rate        = t->t_props.tp_vbitrate * 1000;
			  octx->rc_buffer_size  = octx->bit_rate * 3;
			  // use gop size of 5 seconds
			  octx->gop_size       *= 5;
		  }
      break;

	  case SCT_H264:
		  octx->flags         |= CODEC_FLAG_GLOBAL_HEADER;

		  // Default = "medium". We gain more encoding speed compared to the loss of quality when lowering it _slightly_.
		  // select preset according to system performance and codec type
		  av_dict_set(&opts, "preset",  t->t_props.tp_vcodec_preset, 0);
		  tvhinfo(LS_TRANSCODE, "%04X: Using preset %s", shortid(t), t->t_props.tp_vcodec_preset);

		  // All modern devices should support "high" profile
		  if(strcmp(ocodec->name, "h264_omx") != 0)
			  av_dict_set(&opts, "profile", "high", 0);

		  if (t->t_props.tp_vbitrate < 64) {
			  // encode with specified quality and optimize for low latency
			  // valid values for quality are 1-51, smaller means better quality, use 15 as default
			  av_dict_set_int__(&opts,      "crf", t->t_props.tp_vbitrate == 0 ? 15 : MIN(51, t->t_props.tp_vbitrate), 0);
			  // tune "zerolatency" removes as much encoder latency as possible
			  av_dict_set(&opts,      "tune", "zerolatency", 0);
		  }
		  else
		  {
			  // encode with specified bitrate and optimize for high compression
			  octx->bit_rate        = t->t_props.tp_vbitrate * 1000;
			  octx->rc_max_rate     = ceil(octx->bit_rate * 1.25);
			  octx->rc_buffer_size  = octx->rc_max_rate * 3;
			  // force-cfr=1 is needed for correct bitrate calculation (tune "zerolatency" also sets this)
			  av_dict_set(&opts,      "x264opts", "force-cfr=1", 0);
			  // use gop size of 5 seconds
			  octx->gop_size       *= 5;
		  }
      break;

	  case SCT_HEVC:
		  // on all hardware ultrafast (or maybe superfast) should be safe
		  // select preset according to system performance
		  av_dict_set(&opts, "preset",  t->t_props.tp_vcodec_preset, 0);
		  tvhinfo(LS_TRANSCODE, "%04X: Using preset %s", shortid(t), t->t_props.tp_vcodec_preset);

		  // disables encoder features which tend to be bottlenecks for the decoder/player
		  av_dict_set(&opts, "tune",   "fastdecode", 0);

		  if (t->t_props.tp_vbitrate < 64) {
			  // encode with specified quality
			  // valid values for crf are 1-51, smaller means better quality
			  // use 18 as default
			  av_dict_set_int__(&opts, "crf", t->t_props.tp_vbitrate == 0 ? 18 : MIN(51, t->t_props.tp_vbitrate), 0);

			  // the following is equivalent to tune=zerolatency for presets: ultra/superfast
			  av_dict_set(&opts, "x265-params", "bframes=0",        0);
			  av_dict_set(&opts, "x265-params", ":rc-lookahead=0",  AV_DICT_APPEND);
			  av_dict_set(&opts, "x265-params", ":scenecut=0",      AV_DICT_APPEND);
			  av_dict_set(&opts, "x265-params", ":frame-threads=1", AV_DICT_APPEND);
		  }
		  else
		  {
			  int bitrate, maxrate, bufsize;
			  bitrate = (t->t_props.tp_vbitrate > max_bitrate) ? max_bitrate : t->t_props.tp_vbitrate;
			  maxrate = ceil(bitrate * 1.25);
			  bufsize = maxrate * 3;

			  tvhdebug(LS_TRANSCODE, "tuning HEVC encoder for ABR rate control, "
					  "bitrate: %dkbps, vbv-bufsize: %dkbits, vbv-maxrate: %dkbps",
					  bitrate, bufsize, maxrate);

			  // this is the same as setting --bitrate=bitrate
			  octx->bit_rate = bitrate * 1000;

			  av_dict_set(&opts,       "x265-params", "vbv-bufsize=",  0);
			  av_dict_set_int__(&opts, "x265-params", bufsize,         AV_DICT_APPEND);
			  av_dict_set(&opts,       "x265-params", ":vbv-maxrate=", AV_DICT_APPEND);
			  av_dict_set_int__(&opts, "x265-params", maxrate,         AV_DICT_APPEND);
			  av_dict_set(&opts,       "x265-params", ":strict-cbr=1", AV_DICT_APPEND);
		  }
		  // reduce key frame interface for live streaming
		  av_dict_set(&opts, "x265-params", ":keyint=49:min-keyint=15", AV_DICT_APPEND);
      break;

	  default:
      break;
	  }

	  if (avcodec_open2(octx, ocodec, &opts) < 0)
	  {
		  tvherror(LS_TRANSCODE, "%04X: Unable to open %s encoder",
               shortid(t), ocodec->name);
		  transcoder_stream_invalidate(ts);
		  goto cleanup;
	  }
  }

  pop = encoder->input_pipeline->pop_pointer;
  ipipeline = encoder->input_pipeline;
  if(pop != encoder->input_pipeline->push_pointer)
  {
  	  iframe = encoder->input_pipeline->vid_frames[pop];
	  /*
 	   * One frame available out from the filter chain, encode it
	   */
  	  tvhtrace(LS_TRANSCODE, "%04X: Encoder: Processing input frame %d (ts %d), pts %" PRIu64 ", dts %" PRIu64 ", duration %" PRIu64 "",
  			  shortid(t), pop, ipipeline->stage_timestamp, iframe->pkt_pts, iframe->pkt_dts, iframe->pkt_duration);
	  tvhtrace(LS_TRANSCODE, "%04X:          Input frame %x width %d, height %d", shortid(t), (unsigned int)iframe,
			  iframe->width, iframe->height);
	  tvhtrace(LS_TRANSCODE, "%04X:          Input frame format %s", shortid(t),
			  av_get_pix_fmt_name(iframe->format));

	  encoder->input_pipeline->pop_pointer++;

	  if(encoder->input_pipeline->pop_pointer >= encoder->input_pipeline->pipeline_size)
		  encoder->input_pipeline->pop_pointer = 0;

	  ret = avcodec_encode_video2(octx, &encoder->packet, iframe, &got_output);
	  if (ret < 0) {
		  tvherror(LS_TRANSCODE, "%04X: Error encoding frame", shortid(t));
		  transcoder_stream_invalidate(ts);
		  goto cleanup;
	  }

	  av_frame_unref(iframe);
  }
  else
	  tvhtrace(LS_TRANSCODE, "%04X: Encoder: no available input buffer", shortid(t));

  if (got_output)
  {
      tvhtrace(LS_TRANSCODE, "%04X: Encoder: Encoded packet pts %" PRIu64 ", dts %" PRIu64 "\n", shortid(t), encoder->packet.pts, encoder->packet.dts);
	  send_video_packet(t, ts, encoder, &encoder->packet, octx);
  }
#else
#if !USE_THREADING
  transcoder_encoder_stage(&vs->video_stages[2]);
#endif
#endif


	pthread_mutex_lock(vs->condition_mutex);
	vs->stage_run_mask = 0x6;
	pthread_mutex_unlock(vs->condition_mutex);
	pthread_cond_broadcast(vs->condition_sync);

cleanup:

  stage_timestamp++;

  if(encoder)
	  av_free_packet(&encoder->packet);

  if(decoder)
	  av_free_packet(&decoder->packet);

  if(opts)
    av_dict_free(&opts);

  pkt_ref_dec(pkt);
}


/**
 *
 */
static void
transcoder_packet(transcoder_t *t, th_pkt_t *pkt)
{
  transcoder_stream_t *ts;
  streaming_message_t *sm;

  LIST_FOREACH(ts, &t->t_stream_list, ts_link) {
    if (pkt->pkt_componentindex == ts->ts_index) {
      if (pkt->pkt_payload) {
        ts->ts_handle_pkt(t, ts, pkt);
      } else {
        sm = streaming_msg_create_pkt(pkt);
        streaming_target_deliver2(ts->ts_target, sm);
        pkt_ref_dec(pkt);
      }
      return;
    }
  }
  pkt_ref_dec(pkt);
}


/**
 *
 */
static void
transcoder_destroy_stream(transcoder_t *t, transcoder_stream_t *ts)
{
  if (ts->ts_input_gh)
    pktbuf_ref_dec(ts->ts_input_gh);
  free(ts);
}


/**
 *
 */
static int
transcoder_init_stream(transcoder_t *t, streaming_start_component_t *ssc)
{
  transcoder_stream_t *ts = calloc(1, sizeof(transcoder_stream_t));

  ts->ts_index      = ssc->ssc_index;
  ts->ts_type       = ssc->ssc_type;
  ts->ts_target     = t->t_output;
  ts->ts_handle_pkt = transcoder_stream_packet;
  ts->ts_destroy    = transcoder_destroy_stream;

  LIST_INSERT_HEAD(&t->t_stream_list, ts, ts_link);

  if(ssc->ssc_gh) {
    pktbuf_ref_inc(ssc->ssc_gh);
    ts->ts_input_gh = ssc->ssc_gh;
    pktbuf_ref_inc(ssc->ssc_gh);
  }

  tvhinfo(LS_TRANSCODE, "%04X: %d:%s ==> Passthrough",
	  shortid(t), ssc->ssc_index,
	  streaming_component_type2txt(ssc->ssc_type));

  return 1;
}


/**
 *
 */
static void
transcoder_destroy_subtitle(transcoder_t *t, transcoder_stream_t *ts)
{
  subtitle_stream_t *ss = (subtitle_stream_t*)ts;

  if(ss->sub_ictx) {
    av_freep(&ss->sub_ictx->extradata);
    ss->sub_ictx->extradata_size = 0;
    avcodec_close(ss->sub_ictx);
    av_free(ss->sub_ictx);
  }

  if(ss->sub_octx) {
    avcodec_close(ss->sub_octx);
    av_free(ss->sub_octx);
  }

  transcoder_destroy_stream(t, ts);
}


/**
 *
 */
static int
transcoder_init_subtitle(transcoder_t *t, streaming_start_component_t *ssc)
{
  subtitle_stream_t *ss;
  AVCodec *icodec, *ocodec;
  transcoder_props_t *tp = &t->t_props;
  int sct;

  if (tp->tp_scodec[0] == '\0')
    return 0;

  else if (!strcmp(tp->tp_scodec, "copy"))
    return transcoder_init_stream(t, ssc);

  else if (!(icodec = transcoder_get_decoder(t, ssc->ssc_type)))
    return transcoder_init_stream(t, ssc);

  else if (!(ocodec = transcoder_get_encoder(t, tp->tp_scodec)))
    return transcoder_init_stream(t, ssc);

  sct = codec_id2streaming_component_type(ocodec->id);

  if (sct == ssc->ssc_type)
    return transcoder_init_stream(t, ssc);

  ss = calloc(1, sizeof(subtitle_stream_t));

  ss->ts_index      = ssc->ssc_index;
  ss->ts_type       = sct;
  ss->ts_target     = t->t_output;
  ss->ts_handle_pkt = transcoder_stream_subtitle;
  ss->ts_destroy    = transcoder_destroy_subtitle;
  if (ssc->ssc_gh) {
    ss->ts_input_gh = ssc->ssc_gh;
    pktbuf_ref_inc(ssc->ssc_gh);
  }

  ss->sub_icodec = icodec;
  ss->sub_ocodec = ocodec;

  ss->sub_ictx = avcodec_alloc_context3_tvh(icodec);
  ss->sub_octx = avcodec_alloc_context3_tvh(ocodec);

  LIST_INSERT_HEAD(&t->t_stream_list, (transcoder_stream_t*)ss, ts_link);

  tvhinfo(LS_TRANSCODE, "%04X: %d:%s ==> %s (%s)",
	  shortid(t), ssc->ssc_index,
	  streaming_component_type2txt(ssc->ssc_type),
	  streaming_component_type2txt(ss->ts_type),
	  ocodec->name);

  ssc->ssc_type = sct;
  ssc->ssc_gh = NULL;

  return 1;
}


/**
 *
 */
static void
transcoder_destroy_audio(transcoder_t *t, transcoder_stream_t *ts)
{
  audio_stream_t *as = (audio_stream_t*)ts;

  if(as->aud_ictx) {
    av_freep(&as->aud_ictx->extradata);
    as->aud_ictx->extradata_size = 0;
    avcodec_close(as->aud_ictx);
    av_free(as->aud_ictx);
  }

  if(as->aud_octx) {
    avcodec_close(as->aud_octx);
    av_free(as->aud_octx);
  }

  if ((as->resample_context) && as->resample_is_open )
      avresample_close(as->resample_context);
  avresample_free(&as->resample_context);

  av_audio_fifo_free(as->fifo);

  transcoder_destroy_stream(t, ts);
}


/**
 *
 */
static int
transcoder_init_audio(transcoder_t *t, streaming_start_component_t *ssc)
{
  audio_stream_t *as;
  transcoder_stream_t *ts;
  AVCodec *icodec, *ocodec;
  transcoder_props_t *tp = &t->t_props;
  int sct;

  if (tp->tp_acodec[0] == '\0')
    return 0;

  else if (!strcmp(tp->tp_acodec, "copy"))
    return transcoder_init_stream(t, ssc);

  else if (!(icodec = transcoder_get_decoder(t, ssc->ssc_type)))
    return transcoder_init_stream(t, ssc);

  else if (!(ocodec = transcoder_get_encoder(t, tp->tp_acodec)))
    return transcoder_init_stream(t, ssc);

  LIST_FOREACH(ts, &t->t_stream_list, ts_link)
    if (SCT_ISAUDIO(ts->ts_type))
       return 0;

  sct = codec_id2streaming_component_type(ocodec->id);

  // Don't transcode to identical output codec unless the streaming profile specifies a bitrate limiter.
  if (sct == ssc->ssc_type && t->t_props.tp_abitrate < 16) {
    return transcoder_init_stream(t, ssc);
  }

  as = calloc(1, sizeof(audio_stream_t));

  as->ts_index      = ssc->ssc_index;
  as->ts_type       = sct;
  as->ts_target     = t->t_output;
  as->ts_handle_pkt = transcoder_stream_audio;
  as->ts_destroy    = transcoder_destroy_audio;
  if (ssc->ssc_gh) {
    as->ts_input_gh = ssc->ssc_gh;
    pktbuf_ref_inc(ssc->ssc_gh);
  }

  as->aud_icodec = icodec;
  as->aud_ocodec = ocodec;

  as->aud_ictx = avcodec_alloc_context3_tvh(icodec);
  as->aud_octx = avcodec_alloc_context3_tvh(ocodec);

  LIST_INSERT_HEAD(&t->t_stream_list, (transcoder_stream_t*)as, ts_link);

  tvhinfo(LS_TRANSCODE, "%04X: %d:%s ==> %s (%s)",
	  shortid(t), ssc->ssc_index,
	  streaming_component_type2txt(ssc->ssc_type),
	  streaming_component_type2txt(as->ts_type),
	  ocodec->name);

  ssc->ssc_type     = sct;
  ssc->ssc_gh       = NULL;

  if(tp->tp_channels > 0)
    as->aud_channels = tp->tp_channels;
  if(tp->tp_abitrate > 0)
    as->aud_bitrate = tp->tp_abitrate * 1000;

  as->resample_context = NULL;
  as->fifo = NULL;
  as->resample = 0;

  return 1;
}


/**
 *
 */
static void
transcoder_destroy_video(transcoder_t *t, transcoder_stream_t *ts)
{
  int i, k, j;
  video_stream_t *vs = (video_stream_t*)ts;

  if(vs->video_stages)
  {
	  for(i = 0; i < vs->ts_stages; i++)
	  {
	    if(vs->video_stages[i].type == TS_DECODER_STAGE)
	    {
	    	av_freep(&vs->video_stages[i].stage->decoder.vid_ictx->extradata);
	    	vs->video_stages[i].stage->decoder.vid_ictx->extradata = 0;
	    	avcodec_close(vs->video_stages[i].stage->decoder.vid_ictx);
	    	av_free(vs->video_stages[i].stage->decoder.vid_ictx);

	    	if(vs->video_stages[i].stage->decoder.output_pipeline)
	    	{
	    		for(k = 0; k < vs->ts_stages; k++)
	    		{
	    			if(vs->video_stages[i].stage->decoder.output_pipeline->vid_frames[k])
	    				av_free(vs->video_stages[i].stage->decoder.output_pipeline->vid_frames[k]);
	    		}
	    		free(vs->video_stages[i].stage->decoder.output_pipeline->vid_frames);
	    		free(vs->video_stages[i].stage->decoder.output_pipeline);
	    	}

	    	free(vs->video_stages[i].stage);
	    }

	    if(vs->video_stages[i].type == TS_FILTER_STAGE)
	    {
	    	for(j = 0; j < vs->video_stages[i].number_of_stages; j++)
	    	{
		    	if(vs->video_stages[i].stage[j].filter.output_pipeline)
		    	{
		    		for(k = 0; k < vs->ts_stages; k++)
		    		{
		    			if(vs->video_stages[i].stage[j].filter.output_pipeline->vid_frames[k])
		    				av_free(vs->video_stages[i].stage[j].filter.output_pipeline->vid_frames[k]);
		    		}
		    		free(vs->video_stages[i].stage[j].filter.output_pipeline->vid_frames);
		    		free(vs->video_stages[i].stage[j].filter.output_pipeline);
		    	}

		    	if (vs->video_stages[i].stage[j].filter.flt_graph)
		    	{
		    	    avfilter_graph_free(&vs->video_stages[i].stage[j].filter.flt_graph);
		    	    vs->video_stages[i].stage[j].filter.flt_graph = NULL;
		    	}
	    	}
	    	free(vs->video_stages[i].stage);
	    }

	    if(vs->video_stages[i].type == TS_ENCODER_STAGE)
	    {
	    	avcodec_close(vs->video_stages[i].stage->encoder.vid_octx);
	    	av_free(vs->video_stages[i].stage->encoder.vid_octx);
	    	free(vs->video_stages[i].stage);
	    }
	  }

      free(vs->video_stages);
  }

  if (vs->vid_first_pkt)
    pkt_ref_dec(vs->vid_first_pkt);

  transcoder_destroy_stream(t, ts);
}


/**
 *
 */
static int
transcoder_init_video(transcoder_t *t, streaming_start_component_t *ssc)
{
  video_stream_t *vs;
  AVCodec *icodec, *ocodec;
  transcoder_props_t *tp = &t->t_props;
  pthread_cond_t *cv;
  pthread_mutex_t *mutex;
  int sct, i, k, ret;

  if (tp->tp_vcodec[0] == '\0')
    return 0;

  else if (!strcmp(tp->tp_vcodec, "copy"))
    return transcoder_init_stream(t, ssc);

  else if (!(icodec = transcoder_get_decoder_video(t, ssc->ssc_type)))
    return transcoder_init_stream(t, ssc);

  else if (!(ocodec = transcoder_get_encoder(t, tp->tp_vcodec)))
    return transcoder_init_stream(t, ssc);

  cv = malloc(sizeof(pthread_cond_t));
  mutex = malloc(sizeof(pthread_mutex_t));

  ret = pthread_cond_init(cv,  NULL);
  if(ret < 0)
  {
	  tvherror(LS_TRANSCODE, "%04X: Unable to init pthread_cond_init, ret %d", shortid(t), ret);
	  return ret;
  }

  ret = pthread_mutex_init(mutex, NULL);
  if(ret < 0)
  {
	  tvherror(LS_TRANSCODE, "%04X: Unable to init pthread_mutex_init, ret %d", shortid(t), ret);
	  return ret;
  }

  sct = codec_id2streaming_component_type(ocodec->id);

  vs = calloc(1, sizeof(video_stream_t));
  vs->video_stages = calloc(NUMBER_OF_VIDEO_STAGES, sizeof(video_stage_t));

  vs->t 			= t;
  vs->condition_mutex = mutex;
  vs->condition_sync = cv;

  vs->ts_stages     = NUMBER_OF_VIDEO_STAGES;
  vs->ts_index      = ssc->ssc_index;
  vs->ts_type       = sct;
  vs->ts_target     = t->t_output;
  vs->ts_handle_pkt = transcoder_stream_video;
  vs->ts_destroy    = transcoder_destroy_video;
  if (ssc->ssc_gh) {
    vs->ts_input_gh = ssc->ssc_gh;
    pktbuf_ref_inc(ssc->ssc_gh);
  }

  // Decoder
  vs->video_stages[0].type = TS_DECODER_STAGE;
  vs->video_stages[0].this_stage_number = 0;
  vs->video_stages[0].vs = vs;
  vs->video_stages[0].condition_sync = cv;
  vs->video_stages[0].condition_mutex = mutex;
  vs->video_stages[0].prev = NULL;
  vs->video_stages[0].next = &vs->video_stages[1];
  vs->video_stages[0].number_of_stages = 1;
  vs->video_stages[0].stage = calloc(1,sizeof(union stage));
  vs->video_stages[0].stage->decoder.vid_icodec = icodec;
  vs->video_stages[0].stage->decoder.vid_ictx = avcodec_alloc_context3_tvh(icodec);
  vs->video_stages[0].stage->decoder.output_pipeline = calloc(1, sizeof(avframes_pipeline_t));
  vs->video_stages[0].stage->decoder.output_pipeline->pipeline_size = NUMBER_OF_VIDEO_STAGES;
  vs->video_stages[0].stage->decoder.output_pipeline->num_of_frames_available = 0;
  vs->video_stages[0].stage->decoder.output_pipeline->push_pointer = 0;
  vs->video_stages[0].stage->decoder.output_pipeline->pop_pointer = 0;
  vs->video_stages[0].stage->decoder.output_pipeline->vid_frames = calloc(NUMBER_OF_VIDEO_STAGES, sizeof(AVFrame *));

  for(i = 0; i < NUMBER_OF_VIDEO_STAGES; i++)
  {
	  vs->video_stages[0].stage->decoder.output_pipeline->vid_frames[i] = av_frame_alloc();
	  av_frame_unref(vs->video_stages[0].stage->decoder.output_pipeline->vid_frames[i]);
  }

  // Filters
  vs->video_stages[1].type = TS_FILTER_STAGE;
  vs->video_stages[1].this_stage_number = 1;
  vs->video_stages[1].vs = vs;
  vs->video_stages[1].condition_sync = cv;
  vs->video_stages[1].condition_mutex = mutex;
  vs->video_stages[1].prev = &vs->video_stages[0];
  vs->video_stages[1].next = &vs->video_stages[2];
  vs->video_stages[1].number_of_stages = NUMBER_OF_FILTER_STAGES;
  vs->video_stages[1].stage = calloc(NUMBER_OF_FILTER_STAGES, sizeof(union stage));


  // Init here the filters
  for(k = 0; k < NUMBER_OF_FILTER_STAGES; k++)
  {
	  if(k == 0) // First filter shall take the decoder pipeline output
		  vs->video_stages[1].stage[k].filter.input_pipeline = vs->video_stages[0].stage->decoder.output_pipeline;
	  else
		  vs->video_stages[1].stage[k].filter.input_pipeline = vs->video_stages[1].stage[k-1].filter.output_pipeline;

	  vs->video_stages[1].stage[k].filter.flt_graph = NULL;
	  vs->video_stages[1].stage[k].filter.output_pipeline = calloc(1, sizeof(avframes_pipeline_t));
	  vs->video_stages[1].stage[k].filter.output_pipeline->pipeline_size = NUMBER_OF_VIDEO_STAGES;
	  vs->video_stages[1].stage[k].filter.output_pipeline->num_of_frames_available = 0;
	  vs->video_stages[1].stage[k].filter.output_pipeline->push_pointer = 0;
	  vs->video_stages[1].stage[k].filter.output_pipeline->pop_pointer = 0;
	  vs->video_stages[1].stage[k].filter.output_pipeline->vid_frames = calloc(1, NUMBER_OF_VIDEO_STAGES*sizeof(AVFrame *));

	  for(i = 0; i < NUMBER_OF_VIDEO_STAGES; i++)
	  {
		  vs->video_stages[1].stage[k].filter.output_pipeline->vid_frames[i] = av_frame_alloc();
		  av_frame_unref(vs->video_stages[1].stage[k].filter.output_pipeline->vid_frames[i]);
	  }
  }

  // Encoder
  vs->video_stages[2].type = TS_ENCODER_STAGE;
  vs->video_stages[2].this_stage_number = 2;
  vs->video_stages[2].vs = vs;
  vs->video_stages[2].condition_sync = cv;
  vs->video_stages[2].condition_mutex = mutex;
  vs->video_stages[2].prev = &vs->video_stages[1];
  vs->video_stages[2].next = NULL;
  vs->video_stages[2].number_of_stages = 1;
  vs->video_stages[2].stage = calloc(1,sizeof(union stage));
  vs->video_stages[2].stage->encoder.vid_ocodec = ocodec;
  vs->video_stages[2].stage->encoder.vid_octx = avcodec_alloc_context3_tvh(ocodec);
  vs->video_stages[2].stage->encoder.input_pipeline = vs->video_stages[1].stage[NUMBER_OF_FILTER_STAGES-1].filter.output_pipeline;

//  if (t->t_props.tp_nrprocessors)
//    vs->vid_octx->thread_count = t->t_props.tp_nrprocessors;
  vs->video_stages[2].stage->encoder.vid_octx->thread_count = 1;

  LIST_INSERT_HEAD(&t->t_stream_list, (transcoder_stream_t*)vs, ts_link);


  if(tp->tp_resolution > 0) {
    vs->vid_height = MIN(tp->tp_resolution, ssc->ssc_height);
    vs->vid_height += vs->vid_height & 1; /* Must be even */

    double aspect = (double)ssc->ssc_width / ssc->ssc_height;
    vs->vid_width = vs->vid_height * aspect;
    vs->vid_width += vs->vid_width & 1;   /* Must be even */
  } else {
    vs->vid_height = ssc->ssc_height;
    vs->vid_width  = ssc->ssc_width;
  }

  tvhinfo(LS_TRANSCODE, "%04X: %d:%s %dx%d ==> %s %dx%d (%s)",
          shortid(t),
          ssc->ssc_index,
          streaming_component_type2txt(ssc->ssc_type),
          ssc->ssc_width,
          ssc->ssc_height,
          streaming_component_type2txt(vs->ts_type),
          vs->vid_width,
          vs->vid_height,
          ocodec->name);

  ssc->ssc_type   = sct;
  ssc->ssc_width  = vs->vid_width;
  ssc->ssc_height = vs->vid_height;
  ssc->ssc_gh     = NULL;

  /*
   * Create tasks
   */
//  pthread_create(&vs->video_stages[0].thread, NULL, transcoder_stage_thread, &vs->video_stages[0]);
  pthread_create(&vs->video_stages[1].thread, NULL, transcoder_stage_thread, &vs->video_stages[1]);
  pthread_create(&vs->video_stages[2].thread, NULL, transcoder_stage_thread, &vs->video_stages[2]);

  return 1;
}


/**
 * Figure out how many streams we will use.
 */
static int
transcoder_calc_stream_count(transcoder_t *t, streaming_start_t *ss) {
  int i = 0;
  int video = 0;
  int audio = 0;
  int subtitle = 0;
  streaming_start_component_t *ssc = NULL;

  for (i = 0; i < ss->ss_num_components; i++) {
    ssc = &ss->ss_components[i];

    if (ssc->ssc_disabled)
      continue;

    if (SCT_ISVIDEO(ssc->ssc_type)) {
      if (t->t_props.tp_vcodec[0] == '\0')
	video = 0;
      else if (!strcmp(t->t_props.tp_vcodec, "copy"))
	video++;
      else
	video = 1;

    } else if (SCT_ISAUDIO(ssc->ssc_type)) {
      if (t->t_props.tp_acodec[0] == '\0')
	audio = 0;
      else if (!strcmp(t->t_props.tp_acodec, "copy"))
	audio++;
      else
	audio = 1;

    } else if (SCT_ISSUBTITLE(ssc->ssc_type)) {
      if (t->t_props.tp_scodec[0] == '\0')
	subtitle = 0;
      else if (!strcmp(t->t_props.tp_scodec, "copy"))
	subtitle++;
      else
	subtitle = 1;
    }
  }

  tvhtrace(LS_TRANSCODE, "%04X: transcoder_calc_stream_count=%d (video=%d, audio=%d, subtitle=%d)",
           shortid(t), (video + audio + subtitle), video, audio, subtitle);


  return (video + audio + subtitle);
}


/**
 *
 */
static streaming_start_t *
transcoder_start(transcoder_t *t, streaming_start_t *src)
{
  int i, j, n, rc;
  streaming_start_t *ss;
  transcoder_props_t *tp = &t->t_props;
  char* requested_lang;

  n = transcoder_calc_stream_count(t, src);
  ss = calloc(1, (sizeof(streaming_start_t) +
		  sizeof(streaming_start_component_t) * n));

  ss->ss_refcount       = 1;
  ss->ss_num_components = n;
  ss->ss_pcr_pid        = src->ss_pcr_pid;
  ss->ss_pmt_pid        = src->ss_pmt_pid;
  service_source_info_copy(&ss->ss_si, &src->ss_si);

  requested_lang = tp->tp_language;

  if (requested_lang[0] != '\0')
  {
      for (i = 0; i < src->ss_num_components; i++) {
        streaming_start_component_t *ssc_src = &src->ss_components[i];
        if (SCT_ISAUDIO(ssc_src->ssc_type) && !strcmp(tp->tp_language, ssc_src->ssc_lang))
          break;
      }

      if (i == src->ss_num_components)
      {
        tvhinfo(LS_TRANSCODE, "Could not find requestd lang [%s] in stream, using first one", tp->tp_language);
        requested_lang[0] = '\0';
      }
  }

  for (i = j = 0; i < src->ss_num_components && j < n; i++) {
    streaming_start_component_t *ssc_src = &src->ss_components[i];
    streaming_start_component_t *ssc = &ss->ss_components[j];

    if (ssc_src->ssc_disabled)
      continue;

    *ssc = *ssc_src;

    if (SCT_ISVIDEO(ssc->ssc_type))
      rc = transcoder_init_video(t, ssc);
    else if (SCT_ISAUDIO(ssc->ssc_type) && (requested_lang[0] == '\0' || !strcmp(requested_lang, ssc->ssc_lang)))
      rc = transcoder_init_audio(t, ssc);
    else if (SCT_ISSUBTITLE(ssc->ssc_type))
      rc = transcoder_init_subtitle(t, ssc);
    else
      rc = 0;

    if(!rc)
      tvhinfo(LS_TRANSCODE, "%04X: %d:%s ==> Filtered",
	      shortid(t), ssc->ssc_index,
	      streaming_component_type2txt(ssc->ssc_type));
    else
      j++;
  }

  return ss;
}


/**
 *
 */
static void
transcoder_stop(transcoder_t *t)
{
  transcoder_stream_t *ts;

  while ((ts = LIST_FIRST(&t->t_stream_list))) {
    LIST_REMOVE(ts, ts_link);

    if (ts->ts_destroy)
      ts->ts_destroy(t, ts);
  }
}


/**
 *
 */
static void
transcoder_input(void *opaque, streaming_message_t *sm)
{
  transcoder_t *t = opaque;
  streaming_start_t *ss;

  switch (sm->sm_type) {
  case SMT_PACKET:
    transcoder_packet(t, sm->sm_data);
    sm->sm_data = NULL;
    streaming_msg_free(sm);
    break;

  case SMT_START:
    transcoder_stop(t);
    ss = transcoder_start(t, sm->sm_data);
    streaming_start_unref(sm->sm_data);
    sm->sm_data = ss;

    streaming_target_deliver2(t->t_output, sm);
    break;

  case SMT_STOP:
    transcoder_stop(t);
    /* Fallthrough */

  case SMT_GRACE:
  case SMT_SPEED:
  case SMT_SKIP:
  case SMT_TIMESHIFT_STATUS:
  case SMT_EXIT:
  case SMT_SERVICE_STATUS:
  case SMT_SIGNAL_STATUS:
  case SMT_DESCRAMBLE_INFO:
  case SMT_NOSTART:
  case SMT_NOSTART_WARN:
  case SMT_MPEGTS:
    streaming_target_deliver2(t->t_output, sm);
    break;
  }
}

static htsmsg_t *
transcoder_input_info(void *opaque, htsmsg_t *list)
{
  transcoder_t *t = opaque;
  streaming_target_t *st = t->t_output;
  htsmsg_add_str(list, NULL, "transcoder input");
  return st->st_ops.st_info(st->st_opaque, list);;
}

static streaming_ops_t transcoder_input_ops = {
  .st_cb   = transcoder_input,
  .st_info = transcoder_input_info
};



/**
 *
 */
streaming_target_t *
transcoder_create(streaming_target_t *output)
{
  static uint32_t transcoder_id = 0;
  transcoder_t *t = calloc(1, sizeof(transcoder_t));

  t->t_id = ++transcoder_id;
  if (!t->t_id) t->t_id = ++transcoder_id;
  t->t_output = output;

  streaming_target_init(&t->t_input, &transcoder_input_ops, t, 0);

  return &t->t_input;
}


/**
 *
 */
void
transcoder_set_properties(streaming_target_t *st,
			  transcoder_props_t *props)
{
  transcoder_t *t = (transcoder_t *)st;
  transcoder_props_t *tp = &t->t_props;

  strncpy(tp->tp_vcodec, props->tp_vcodec, sizeof(tp->tp_vcodec)-1);
  strncpy(tp->tp_vcodec_preset, props->tp_vcodec_preset, sizeof(tp->tp_vcodec_preset)-1);
  strncpy(tp->tp_acodec, props->tp_acodec, sizeof(tp->tp_acodec)-1);
  strncpy(tp->tp_scodec, props->tp_scodec, sizeof(tp->tp_scodec)-1);
  tp->tp_channels   = props->tp_channels;
  tp->tp_vbitrate   = props->tp_vbitrate;
  tp->tp_abitrate   = props->tp_abitrate;
  tp->tp_resolution = props->tp_resolution;

  memcpy(tp->tp_language, props->tp_language, 4);
}


/**
 *
 */
void
transcoder_destroy(streaming_target_t *st)
{
  transcoder_t *t = (transcoder_t *)st;

  transcoder_stop(t);
  free(t);
}


/**
 *
 */
htsmsg_t *
transcoder_get_capabilities(int experimental)
{
  AVCodec *p = NULL;
  streaming_component_type_t sct;
  htsmsg_t *array = htsmsg_create_list(), *m;
  char buf[128];

  while ((p = av_codec_next(p))) {

    if (!libav_is_encoder(p))
      continue;

    if (!WORKING_ENCODER(p->id))
      continue;

    if (((p->capabilities & CODEC_CAP_EXPERIMENTAL) && !experimental) ||
        (p->capabilities & AV_CODEC_CAP_VARIABLE_FRAME_SIZE)) {
      continue;
    }

    sct = codec_id2streaming_component_type(p->id);
    if (sct == SCT_NONE || sct == SCT_UNKNOWN)
      continue;

    m = htsmsg_create_map();
    htsmsg_add_s32(m, "type", sct);
    htsmsg_add_u32(m, "id", p->id);
    htsmsg_add_str(m, "name", p->name);
    snprintf(buf, sizeof(buf), "%s%s",
             p->long_name ?: "",
             (p->capabilities & CODEC_CAP_EXPERIMENTAL) ?
               " (Experimental)" : "");
    if (buf[0] != '\0')
      htsmsg_add_str(m, "long_name", buf);
    htsmsg_add_msg(array, NULL, m);
  }
  return array;
}


/*
 *
 */
void transcoding_init(void)
{
}
