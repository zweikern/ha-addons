(() => {
  const input = document.getElementById('task-search');
  if (!input) return;
  input.addEventListener('input', () => {
    const term = input.value.trim().toLocaleLowerCase();
    document.querySelectorAll('[data-task-search]').forEach(row => {
      row.hidden = !row.dataset.taskSearch.includes(term);
    });
  });
})();
