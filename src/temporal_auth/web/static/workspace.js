/* Progressive form submission; HTMX owns server-rendered progress fragments. */
const token = () => document.querySelector('meta[name="csrf-token"]').content;
document.addEventListener('htmx:configRequest', event => { event.detail.headers['X-CSRF-Token'] = token(); });

function notify(message, error = false) {
  const toast = document.getElementById('toast');
  toast.textContent = message;
  toast.classList.toggle('error', error);
  toast.hidden = false;
  clearTimeout(window.toastTimer);
  window.toastTimer = setTimeout(() => { toast.hidden = true; }, 6000);
}

async function post(url, body) {
  const response = await fetch(url, {method: 'POST', headers: {'Content-Type': 'application/json', 'X-CSRF-Token': token()}, body: JSON.stringify(body || {})});
  const data = await response.json();
  if (!response.ok) throw new Error(typeof data.detail === 'string' ? data.detail : 'The request could not be completed. Reload and try again.');
  return data;
}

const form = document.getElementById('experiment-form');
if (form) {
  const target = form.elements.target;
  function syncFields() {
    const native = ['gitea', 'pocketbase'].includes(target.value);
    for (const section of form.querySelectorAll('[data-scope]')) {
      const show = section.dataset.scope === target.value || (section.dataset.scope === 'native' && native);
      section.hidden = !show;
      section.querySelectorAll('input,select,textarea').forEach(input => { input.disabled = !show; });
    }
    document.getElementById('policy-hint').textContent = native ? 'Apply the annotated local policy, with a 50 ms probe tolerance.' : target.value === 'configured_lab' ? 'Use the timing bound and source declared in your configuration.' : 'Wait 5 seconds plus a 50 ms tolerance after acknowledgement.';
    const message = document.getElementById('form-message');
    message.hidden = true;
  }
  target.addEventListener('change', syncFields);
  syncFields();
  function payload() {
    const data = Object.fromEntries(new FormData(form));
    for (const name of ['seed', 'max_requests', 'max_runtime_seconds']) data[name] = Number(data[name]);
    if (target.value === 'configured_lab') data.reset_authorized = form.elements.reset_authorized.checked;
    return data;
  }
  async function submit(validateOnly) {
    if (!form.reportValidity()) return;
    const button = document.getElementById(validateOnly ? 'validate-config' : 'start-experiment');
    const message = document.getElementById('form-message');
    button.disabled = true;
    message.hidden = true;
    try {
      const data = await post(validateOnly ? '/api/validate' : '/api/jobs', payload());
      if (!validateOnly) { window.location.assign(data.url); return; }
      message.textContent = 'Configuration valid. ' + data.notice + (data.missing_credentials.length ? ' Missing environment references: ' + data.missing_credentials.join(', ') : '');
      message.className = 'notice success';
    } catch (error) {
      message.textContent = error.message;
      message.className = 'notice error';
    } finally { button.disabled = false; message.hidden = false; }
  }
  form.addEventListener('submit', event => { event.preventDefault(); submit(false); });
  document.getElementById('validate-config').addEventListener('click', () => submit(true));
}

document.addEventListener('click', async event => {
  const button = event.target.closest('[data-cancel],[data-replay]');
  if (!button) return;
  button.disabled = true;
  try {
    if (button.dataset.cancel) {
      await post('/api/jobs/' + button.dataset.cancel + '/cancel');
      notify('Cancellation requested. Partial evidence will be retained.');
      if (window.htmx) htmx.ajax('GET', location.pathname + '/live', {target: '#run-live', swap: 'outerHTML'});
    } else {
      const result = await post('/api/jobs/' + button.dataset.replay + '/replay');
      location.assign(result.url);
    }
  } catch (error) { notify(error.message, true); button.disabled = false; }
});
document.addEventListener('htmx:sendError', () => notify('Connection interrupted. Reload when the local server is available.', true));
