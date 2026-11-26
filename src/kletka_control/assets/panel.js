const closeAllMenus = () => document.querySelectorAll('details[data-menu][open]').forEach((d) => d.removeAttribute('open'));

function placeMenu(d) {
  const panel = d.querySelector('[data-menu-panel]');
  const trigger = d.querySelector('summary');
  if (!panel || !trigger) return;
  const r = trigger.getBoundingClientRect();
  panel.style.position = 'fixed';
  panel.style.top = `${Math.round(r.bottom + 4)}px`;
  panel.style.right = `${Math.max(8, Math.round(window.innerWidth - r.right))}px`;
  panel.style.left = 'auto';
}

document.addEventListener('toggle', (e) => {
  if (e.target.tagName === 'DETAILS' && e.target.hasAttribute('data-menu') && e.target.open) placeMenu(e.target);
}, true);

document.addEventListener('click', (e) => {
  document.querySelectorAll('details[data-menu][open]').forEach((d) => {
    if (!d.contains(e.target)) d.removeAttribute('open');
  });
});

document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeAllMenus();
});

window.addEventListener('resize', closeAllMenus);
window.addEventListener('scroll', closeAllMenus, true);
