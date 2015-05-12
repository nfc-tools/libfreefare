"-
" Copyright (c) 2010 Romain Tartiere. All rights reserved.
"
" Redistribution and use, with or without modification, are permitted provided
" that the following conditions are met:
" 1. Redistributions of source code must retain the above copyright
"    notice, this list of conditions and the following disclaimer.
"
" THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
" ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
" IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
" ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
" FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
" DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
" OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
" HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
" LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
" OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
" SUCH DAMAGE.

" Additionnal snippets for working with libfreefare in vim with the
" snippetsEmu script:
"   http://www.vim.org/scripts/script.php?script_id=1318
"
" (Contribution for porting this to better snippet handler are welcome!)

if !exists('loaded_snippet') || &cp
    finish
endif

let st = g:snip_start_tag
let et = g:snip_end_tag
let cd = g:snip_elem_delim

exec "Snippet m  mifare_".st.et
exec "Snippet mifare_c mifare_classic_".st.et
exec "Snippet mifare_d mifare_desfire_".st.et
exec "Snippet mifare_u mifare_ultralight_".st.et

exec "Snippet mc mifare_classic_".st.et
exec "Snippet md mifare_desfire_".st.et
exec "Snippet mu mifare_ultralight_".st.et

exec "Snippet MC  MIFARE_CLASSIC".st.et
exec "Snippet MCB  MifareClassicBlock".st.et
exec "Snippet MCBN MifareClassicBlockNumber".st.et
exec "Snippet MCSN MifareClassicSectorNumber".st.et
exec "Snippet MCK  MifareClassicKey".st.et
exec "Snippet MCKT MifareClassicKeyType".st.et

exec "Snippet MD   MIFARE_DESFIRE".st.et
exec "Snippet MDA  MifareDESFireAID".st.et
exec "Snippet MDK  MifareDESFireKey".st.et

exec "Snippet MT  FreefareTag".st.et

exec "Snippet MU   MIFARE_ULTRALIGHT".st.et
exec "Snippet MUP  MifareUltralightPage".st.et
exec "Snippet MUPN MifareUltralightPageNumber".st.et

