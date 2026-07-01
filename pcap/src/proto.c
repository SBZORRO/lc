#include <stddef.h>
#include <stdint.h>
#include <string.h>
#include "src/flow.h"
#include "src/packet.h"

/* protocol section */
const char *servos_requ[] = { NULL, "\x1b", "HO", "RCTY1C", "RSEN0A", "RADA", "SDADS", "SDADE", "SDADC", "SDADB", "RSTI1C", "SSMP0202F", "RADC14", NULL };
const char *servos_requ_filter[] = { NULL, "RCTY1C", "RSEN0A", "RADA", NULL };
const char *servos_resp[] = { NULL, "900PCI", "Servo-s0", "Servo-i0", "Servo-s1", "Servo-i1", NULL };

const char *servou_resp[] = { NULL, "BER2057", "ER2015", "Servo-u0", "Servo-u1", "Servo-n0", "Servo-n1", "Servo-air0", "Servo-air1", NULL };

const char *default_resp = "*2A";

const int EOT = '\x04';
const int ESC = '\x1b';

const char *curve_phase_i = "\x81\x10\x80";
const char *curve_phase_p = "\x81\x20\x80";
const char *curve_phase_e = "\x81\x30\x80";

/* * 发送 */
/*   请求ICC:          1b5136430d */
/*   请求设备ID:       1b5236440d */
/*   请求测量数据CP1:  1b2433460d */
/*   请求测量数据CP2:  1b2b34360d */
/*   请求设备设置:     1b2934340d */
/*   请求文本消息:     1b2a34350d */
/*   请求停止通讯:     1b5537300d */
/*   发送NOP命令:      1b3034420d */
/*   请求实时数据配置: 1b5336450d */
/*   发送实时数据配置: 1b5430303031303130313033303142360d */
/*   启动数据流:       d0c1cfc0c0 */
/*   关闭数据流:       d0c1c0c0c0 */
/*   发送设备ID:       01523031363127536d6f44726167657256656e742730312e30333a30362e303041410d */
/*     0161'SmoDragerVent'01.03:06.00 */

// clang-format off
const char *drager_resp[] = { NULL, "\x1BQ", "\x01Q", "\x1BR", "\x01R", "\x01S", "\x01T", "\x01BV", "\x01$", "\x01+", "\x01)", "\x01*", "\x01""0", "\x1B""0", "\x01\x15", "\x01\x01", NULL };
// clang-format on
const char *drager_cmd[] = {
  NULL,
  /* "\x1b5136430d", */
  /* "\x1b5236440d", */
  /* "\x1b2433460d", */
  /* "\x1b2b34360d", */
  /* "\x1b2934340d", */
  /* "\x1b2a34350d", */
  /* "\x1b5537300d", */
  /* "\x1b3034420d", */
  /* "\x1b5336450d", */
  /* "\x1b5430303031303130313033303142360d", */
  /* "\xd0c1cfc0c0", */
  /* "\xd0c1c0c0c0", */
  /* "\x01523031363127536d6f44726167657256656e742730312e30333a30362e303041410d" */
  NULL
};

static uint8_t
flow_dir_opposite (uint8_t role)
{
  if (role == FLOW_DIR_REQUEST)
    return FLOW_DIR_RESPONSE;
  if (role == FLOW_DIR_RESPONSE)
    return FLOW_DIR_REQUEST;
  return FLOW_DIR_UNKNOWN;
}

uint32_t
contain (uint8_t *str, uint32_t len, const char **targets)
{
  if (len == 0)
    {
      return 0;
    }

  /* Index 0 is reserved so returned type IDs match targets[] indexes. */
  for (uint32_t i = 1; targets[i] != NULL; i++)
    {
      size_t tarlen = strlen (targets[i]);
      int res = memcmp (str, targets[i], MIN (len, tarlen));
      if (res == 0)
        {
          return i;
        }
    }

  for (uint32_t i = 1; targets[i] != NULL; i++)
    {
      void *res = memmem (str, len, targets[i], strlen (targets[i]));
      if (res != NULL)
        {
          return i;
        }
    }
  return 0;
}

bool
flow_should_forward_response (flow_t *flow, flow_detect_t response)
{
  if (flow == NULL || flow->peer == NULL || response.dir != FLOW_DIR_RESPONSE)
    {
      return false;
    }

  flow_detect_t request = flow->peer->detect;
  if (request.dir != FLOW_DIR_REQUEST || request.protocol == 0 || request.type == 0)
    {
      return false;
    }

  /*
   * Request filter policy. Narrow this switch to the exact request message
   * types whose responses should be forwarded.
   */
  switch (request.protocol)
    {
    case FLOW_PROTO_SERVOS:
      switch (request.type)
        {
        case 3:
        case 4:
        case 5:
          return true;
        default:
          return false;
        }
    case FLOW_PROTO_DRAGER:
      return response.protocol == request.protocol;
    default:
      return false;
    }
}

flow_detect_t
detect (flow_t *flow, flow_state_t *state)
{
  flow_detect_t result = { 0 };

  if (state == NULL || state->pkt == NULL || state->size_payload == 0)
    {
      return result;
    }
  if (flow == NULL)
    {
      flow = state->flow;
    }

  uint8_t *payload = state->pkt + state->offset_payload;
  uint32_t len = state->size_payload;
  uint32_t type = 0;

  if (flow->peer == NULL || flow->peer->detect.dir != FLOW_DIR_REQUEST)
    {
      // requ
      type = contain (payload, len, servos_requ);
      if (type != 0)
        {
          result.protocol = FLOW_PROTO_SERVOS;
          result.dir = FLOW_DIR_REQUEST;
          result.type = type;
          goto done;
        }
      type = contain (payload, len, drager_cmd);
      if (type != 0)
        {
          result.protocol = FLOW_PROTO_DRAGER;
          result.dir = FLOW_DIR_REQUEST;
          result.type = type;
          goto done;
        }

      if (memchr (payload, EOT, len) != NULL)
        {
          result.dir = FLOW_DIR_REQUEST;
          goto done;
        }
    }
  // resp
  else if (flow->peer->detect.dir == FLOW_DIR_REQUEST)
    {
      result.protocol = flow->peer->detect.protocol;
      result.dir = FLOW_DIR_RESPONSE;
      result.type = flow->peer->detect.type;
      result.target = flow_should_forward_response (flow, result) ? result.protocol : 0;
      goto done;
    }

done:
  if (flow != NULL)
    {
      flow->detect = result;
      if (result.dir != FLOW_DIR_UNKNOWN && flow->peer != NULL)
        {
          flow->peer->detect.dir = flow_dir_opposite (result.dir);
        }
    }
  return result;
}
