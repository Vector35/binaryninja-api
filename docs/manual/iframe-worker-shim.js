/*!
 * iframe-worker 1.0.4
 * Copyright (c) 2020-2022 Martin Donath <martin.donath@squidfunk.com>
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to
 * deal in the Software without restriction, including without limitation the
 * rights to use, copy, modify, merge, publish, distribute, sublicense, and/or
 * sell copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS
 * IN THE SOFTWARE.
 *
 * Source: https://github.com/squidfunk/iframe-worker/tree/1.0.4
 */
"use strict";(()=>{function c(s,n){parent.postMessage(s,n||"*")}function d(...s){return s.reduce((n,e)=>n.then(()=>new Promise(r=>{let t=document.createElement("script");t.src=e,t.onload=r,document.body.appendChild(t)})),Promise.resolve())}var o=class extends EventTarget{constructor(e){super();this.url=e;this.m=e=>{e.source===this.w&&(this.dispatchEvent(new MessageEvent("message",{data:e.data})),this.onmessage&&this.onmessage(e))};this.e=(e,r,t,i,m)=>{if(r===`${this.url}`){let a=new ErrorEvent("error",{message:e,filename:r,lineno:t,colno:i,error:m});this.dispatchEvent(a),this.onerror&&this.onerror(a)}};let r=document.createElement("iframe");r.hidden=!0,document.body.appendChild(this.iframe=r),this.w.document.open(),this.w.document.write(`<html><body><script>postMessage=${c};importScripts=${d};addEventListener("error",({error})=>{parent.dispatchEvent(new ErrorEvent("error",{filename:"${e}",error}))})<\/script><script src=${e}?${+Date.now()}><\/script></body></html>`),this.w.document.close(),onmessage=this.m,onerror=this.e,this.r=new Promise((t,i)=>{this.w.onload=t,this.w.onerror=i})}terminate(){this.iframe.remove(),onmessage=onerror=null}postMessage(e){this.r.catch().then(()=>{this.w.dispatchEvent(new MessageEvent("message",structuredClone({data:e})))})}get w(){return this.iframe.contentWindow}};window.IFrameWorker=o;location.protocol==="file:"&&(window.Worker=o);})();
