(() => {
  let opener = null;
  const openDialog = (dialog, source) => {
    if (!dialog || dialog.open) return;
    opener = source;
    dialog.showModal();
    dialog.querySelector('input:not([type=hidden]), textarea, select')?.focus();
    document.body.classList.add('pm-modal-open');
  };
  document.addEventListener('click', event => {
    const confirmation = event.target.closest('[data-confirm]');
    if (confirmation && !window.confirm(confirmation.dataset.confirm)) { event.preventDefault(); return; }
    const button = event.target.closest('[data-open-dialog], [data-close-dialog], [data-schedule-id], [data-print-plan]');
    if (!button) return;
    if (button.hasAttribute('data-open-dialog')) {
      openDialog(document.getElementById(button.dataset.openDialog), button);
    } else if (button.hasAttribute('data-close-dialog')) {
      button.closest('dialog')?.close();
    } else if (button.hasAttribute('data-schedule-id')) {
      const id = button.dataset.scheduleId;
      if (!/^\d+$/.test(id)) return;
      const form = document.getElementById('schedule-form');
      form.reset();
      form.elements.end_date.setCustomValidity('');
      form.action = `/tasks/${id}/schedule`;
      form.elements.start_date.value = button.dataset.scheduleStart || '';
      form.elements.end_date.value = button.dataset.scheduleEnd || '';
      document.getElementById('schedule-title').textContent = button.dataset.scheduleTitle;
      document.getElementById('schedule-details').href = `/tasks/${id}`;
      openDialog(document.getElementById('schedule-task'), button);
    } else if (button.hasAttribute('data-print-plan')) {
      window.print();
    }
  });
  document.querySelectorAll('dialog.pm-dialog').forEach(dialog => {
    dialog.addEventListener('close', () => {
      document.body.classList.remove('pm-modal-open');
      if (opener?.isConnected) opener.focus();
    });
    dialog.addEventListener('click', event => {
      if (event.target !== dialog) return;
      const bounds = dialog.getBoundingClientRect();
      if (event.clientX < bounds.left || event.clientX > bounds.right ||
          event.clientY < bounds.top || event.clientY > bounds.bottom) dialog.close();
    });
  });
  document.querySelectorAll('form').forEach(form => {
    const start = form.elements.start_date;
    const end = form.elements.end_date;
    if (!start || !end) return;
    const validate = () => {
      end.setCustomValidity((start.value && !end.value) || (!start.value && end.value)
        ? 'Bitte Start und Ende gemeinsam angeben oder beide Daten leeren.'
        : start.value && end.value < start.value ? 'Das Ende darf nicht vor dem Start liegen.' : '');
    };
    start.addEventListener('input', validate);
    end.addEventListener('input', validate);
    form.addEventListener('submit', event => {
      validate();
      if (!form.reportValidity()) event.preventDefault();
    });
  });
})();
