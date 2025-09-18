// fixi streaming (SSE) extension
// Usage: add ext-fx-sse to an element with fx-action set to the SSE URL.
// When the element triggers (e.g. click), we prevent the normal fetch and
// open an EventSource instead. Server should emit `event: fixi` with a JSON
// payload: { target: string, swap: string, text: string }.

(function(){
  
  // Utility to perform a swap similar to fixi internals
  async function doSwap(cfg){
    if (!cfg || !cfg.target) return;
    const perform = () => {
      const { target, swap, text } = cfg;
      if (/(before|after)(begin|end)/.test(swap)) {
        target.insertAdjacentHTML(swap, text);
      } else if (swap in target) {
        target[swap] = text;
      } else if (swap === 'none') {
        // do nothing
      } else {
        throw new Error("Unknown swap: " + swap);
      }
    };
    const transition = document.startViewTransition?.bind(document);
    if (transition) await transition(perform).finished;
    else perform();
  }

  // Auto-start SSE streams based on a declarative attribute
  // Example markup (progressive enhancement):
  // <div ext-fx-sse-autostart="/events" data-target="#event-log" data-swap="beforeend"></div>
  document.addEventListener("DOMContentLoaded", () => {
    document.querySelectorAll('[ext-fx-sse-autostart]').forEach((el) => {
      const src = el.getAttribute('ext-fx-sse-autostart');
      if (!src) return;
      const targetSelector = el.getAttribute('data-target') || '#event-log';
      const swap = el.getAttribute('data-swap') || 'beforeend';
      try {
        const url = new URL(src, location.href).toString();
        const es = new EventSource(url);
        el.__fixi = el.__fixi || {};
        el.__fixi.sse = es;
        es.addEventListener('fixi', async (event) => {
          try {
            const payload = JSON.parse(event.data);
            const sel = payload.target || targetSelector;
            const sw = payload.swap || swap;
            const text = payload.text ?? '';
            document.querySelectorAll(sel).forEach(async (node) => {
              await doSwap({ target: node, swap: sw, text });
            });
          } catch (e) {
            console.error('SSE autostart fixi event error', e);
          }
        });
        es.addEventListener('error', () => {
          try { es.close(); } catch {}
          if (el.__fixi && el.__fixi.sse === es) el.__fixi.sse = null;
        });
      } catch {}
    });
  });

  document.addEventListener("fx:config", (evt)=>{
    const el = evt.target;
    if (!el || !el.hasAttribute || !el.hasAttribute("ext-fx-sse")) return;

    // Prevent fixi from performing a normal fetch
    evt.preventDefault();

    // Close any previous stream bound to this element
    el.__fixi = el.__fixi || {};
    try { el.__fixi.sse && el.__fixi.sse.close && el.__fixi.sse.close(); } catch {}

    const action = el.getAttribute("fx-action");
    if (!action) return;

    const url = new URL(action, location.href).toString();
    const es = new EventSource(url);
    el.__fixi.sse = es;

    es.addEventListener("fixi", async (event) => {
      try {
        const payload = JSON.parse(event.data);
        document.querySelectorAll(payload.target).forEach(async (node) => {
          const cfg = { target: node, swap: payload.swap || 'innerHTML', text: payload.text ?? '' };
          await doSwap(cfg);
        });
      } catch (e) {
        console.error("SSE fixi event error", e);
      }
    });

    es.addEventListener("error", () => {
      // Stream closed or errored; clean up reference
      try { es.close(); } catch {}
      if (el.__fixi && el.__fixi.sse === es) el.__fixi.sse = null;
    });
  });
})();
