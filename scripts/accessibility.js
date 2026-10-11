(() => {
  const control = document.getElementById('textSize');
  const output = document.getElementById('textSizeValue');
  if (!control || !output) return;
  const key = 'hc_text_size';
  const apply = value => {
    const size = Math.max(90, Math.min(150, Number(value) || 120));
    document.body.style.zoom = `${size}%`;
    control.value = String(size);
    output.value = `${size}%`;
    output.textContent = `${size}%`;
  };
  apply(localStorage.getItem(key) || control.value);
  control.addEventListener('input', () => {
    apply(control.value);
    localStorage.setItem(key, control.value);
  });
  const translationStatus = document.getElementById('translationStatus');
  if (translationStatus) translationStatus.textContent = window.APP_CONFIG?.translationConfigured
    ? 'Full interface translations are enabled through the server translation provider.'
    : 'Common labels have built-in translations. Configure GOOGLE_TRANSLATE_API_KEY on the server for full-page translation.';
})();
