// Static report navigation: evidence links reveal their nested native details.
function revealEvidence() {
  let id;
  try { id = decodeURIComponent(location.hash.slice(1)); } catch { return; }
  const target = document.getElementById(id);
  if (!target) return;
  for (let node = target; node; node = node.parentElement) {
    if (node.tagName === 'DETAILS') node.open = true;
  }
  requestAnimationFrame(() => target.scrollIntoView({ block: 'start' }));
}
window.addEventListener('hashchange', revealEvidence);
document.addEventListener('click', event => {
  const link = event.target.closest('a[href^="#"]');
  if (link) requestAnimationFrame(revealEvidence);
});
if (location.hash) revealEvidence();
