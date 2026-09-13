#!/usr/bin/env bash
set -euo pipefail
fail() { echo "patched TDX quote driver refused: $*" >&2; exit 1; }
[[ $# == 1 ]] || fail 'usage: verify-tdx-quote-hardening.sh DRIVER'
driver=$1; [[ -f "$driver" && ! -L "$driver" ]] || fail 'invalid driver input'
digest=$(sha256sum -- "$driver"); [[ ${digest%% *} == ac7a2fed535b553fbd112bca77d42f7d734fa23e72341ce7437b853d311f582a ]] || fail 'driver digest changed'
[[ $(grep -Fc 'out_len = READ_ONCE(quote_buf->out_len);' "$driver") == 1 ]] || fail 'out_len snapshot changed'
[[ $(grep -Fc 'if (quote_buf->status != GET_QUOTE_SUCCESS)' "$driver") == 1 ]] || fail 'status gate changed'
[[ $(grep -Fc '#define TDX_QUOTE_MAX_LEN' "$driver") == 1 ]] || fail 'maximum definition changed'
[[ $(grep -Fc 'buf = kvmemdup(quote_buf->data, out_len, GFP_KERNEL);' "$driver") == 1 ]] || fail 'copy length changed'
[[ $(grep -Fc 'report->outblob_len = out_len;' "$driver") == 1 ]] || fail 'published length changed'
[[ $(grep -Fc 'quote_buf->out_len' "$driver") == 1 ]] || fail 'shared output length is read more than once'
echo 'patched TDX quote driver verified'
