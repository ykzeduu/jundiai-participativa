(function () {
  var box = document.getElementById('cookie');
  try { if (!localStorage.getItem('aviso-cookies')) box.hidden = false; } catch (e) { box.hidden = false; }
  document.getElementById('cookie-ok').addEventListener('click', function () {
    box.hidden = true;
    try { localStorage.setItem('aviso-cookies', '1'); } catch (e) {}
  });
})();
