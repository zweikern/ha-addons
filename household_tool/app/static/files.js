(function () {
  const form = document.getElementById('files-upload-form');
  const filesInput = document.getElementById('files-input');
  const foldersInput = document.getElementById('folders-input');
  const dropzone = document.getElementById('upload-dropzone');
  const queueInfo = document.getElementById('upload-queue-info');

  if (!form || !filesInput || !foldersInput || !dropzone || !queueInfo) {
    return;
  }

  const queue = [];
  const seen = new Set();

  function formatBytes(num) {
    let value = Math.max(0, Number(num) || 0);
    const units = ['B', 'KB', 'MB', 'GB'];
    let unit = 0;
    while (value >= 1024 && unit < units.length - 1) {
      value /= 1024;
      unit += 1;
    }
    if (unit === 0) {
      return `${Math.round(value)} ${units[unit]}`;
    }
    return `${value.toFixed(1)} ${units[unit]}`;
  }

  function queueKey(file, relativePath) {
    return `${relativePath}|${file.size}|${file.lastModified}`;
  }

  function updateQueueInfo() {
    if (!queue.length) {
      queueInfo.textContent = 'Keine Auswahl';
      return;
    }

    const totalSize = queue.reduce((sum, item) => sum + (item.file.size || 0), 0);
    queueInfo.textContent = `${queue.length} Datei(en), ${formatBytes(totalSize)}`;
  }

  function pushFile(file, relativePath) {
    if (!file) {
      return;
    }
    const rel = (relativePath || file.webkitRelativePath || file.name || '').trim();
    const key = queueKey(file, rel);
    if (seen.has(key)) {
      return;
    }
    seen.add(key);
    queue.push({ file, relativePath: rel || file.name });
  }

  function addFromFileList(fileList) {
    for (const file of Array.from(fileList || [])) {
      pushFile(file, file.webkitRelativePath || file.name);
    }
    updateQueueInfo();
  }

  async function entryFile(entry) {
    return await new Promise((resolve, reject) => {
      entry.file(resolve, reject);
    });
  }

  async function readEntries(reader) {
    const all = [];
    while (true) {
      const entries = await new Promise((resolve, reject) => {
        reader.readEntries(resolve, reject);
      });
      if (!entries || !entries.length) {
        break;
      }
      all.push(...entries);
    }
    return all;
  }

  async function walkEntry(entry, prefix) {
    if (entry.isFile) {
      const file = await entryFile(entry);
      const rel = prefix ? `${prefix}/${file.name}` : file.name;
      pushFile(file, rel);
      return;
    }

    if (!entry.isDirectory) {
      return;
    }

    const nextPrefix = prefix ? `${prefix}/${entry.name}` : entry.name;
    const reader = entry.createReader();
    const children = await readEntries(reader);
    for (const child of children) {
      await walkEntry(child, nextPrefix);
    }
  }

  async function addFromDropItems(items) {
    const entries = [];
    for (const item of Array.from(items || [])) {
      if (item.kind !== 'file') {
        continue;
      }
      if (typeof item.webkitGetAsEntry === 'function') {
        const entry = item.webkitGetAsEntry();
        if (entry) {
          entries.push(entry);
          continue;
        }
      }
      const file = item.getAsFile();
      if (file) {
        pushFile(file, file.name);
      }
    }

    for (const entry of entries) {
      await walkEntry(entry, '');
    }

    updateQueueInfo();
  }

  filesInput.addEventListener('change', function () {
    addFromFileList(filesInput.files);
  });

  foldersInput.addEventListener('change', function () {
    addFromFileList(foldersInput.files);
  });

  dropzone.addEventListener('click', function () {
    filesInput.click();
  });

  dropzone.addEventListener('keydown', function (event) {
    if (event.key === 'Enter' || event.key === ' ') {
      event.preventDefault();
      filesInput.click();
    }
  });

  dropzone.addEventListener('dragover', function (event) {
    event.preventDefault();
    dropzone.classList.add('is-dragover');
  });

  dropzone.addEventListener('dragleave', function () {
    dropzone.classList.remove('is-dragover');
  });

  dropzone.addEventListener('drop', async function (event) {
    event.preventDefault();
    dropzone.classList.remove('is-dragover');
    if (event.dataTransfer && event.dataTransfer.items && event.dataTransfer.items.length) {
      await addFromDropItems(event.dataTransfer.items);
      return;
    }
    if (event.dataTransfer && event.dataTransfer.files) {
      addFromFileList(event.dataTransfer.files);
    }
  });

  form.addEventListener('submit', async function (event) {
    if (!queue.length) {
      return;
    }

    event.preventDefault();

    const submitButton = form.querySelector('button[type="submit"]');
    if (submitButton) {
      submitButton.disabled = true;
      submitButton.textContent = 'Upload läuft ...';
    }

    const relativeHiddenInputs = form.querySelectorAll('input[data-relative-path="1"]');
    relativeHiddenInputs.forEach((el) => el.remove());

    if (typeof DataTransfer !== 'undefined') {
      const transfer = new DataTransfer();
      for (const item of queue) {
        transfer.items.add(item.file);
        const hidden = document.createElement('input');
        hidden.type = 'hidden';
        hidden.name = 'relative_path';
        hidden.value = item.relativePath || item.file.name;
        hidden.setAttribute('data-relative-path', '1');
        form.appendChild(hidden);
      }
      filesInput.files = transfer.files;
      form.submit();
      return;
    }

    const formData = new FormData();
    formData.append('csrf', form.querySelector('input[name="csrf"]').value);
    formData.append('parent_id', form.querySelector('input[name="parent_id"]').value);

    for (const item of queue) {
      formData.append('files', item.file, item.file.name);
      formData.append('relative_path', item.relativePath || item.file.name);
    }

    try {
      const response = await fetch('/files/upload', {
        method: 'POST',
        body: formData,
        credentials: 'same-origin',
      });

      if (response.redirected) {
        window.location.href = response.url;
        return;
      }

      if (response.ok) {
        window.location.reload();
        return;
      }

      window.location.href = '/files?error=upload_failed';
    } catch (_error) {
      window.location.href = '/files?error=upload_failed';
    }
  });

  const previewModal = document.getElementById('image-preview-modal');
  const previewImage = document.getElementById('image-preview-content');
  const previewCaption = document.getElementById('image-preview-caption');
  const previewClose = document.getElementById('image-preview-close');
  const previewPrev = document.getElementById('image-preview-prev');
  const previewNext = document.getElementById('image-preview-next');
  const previewButtons = Array.from(document.querySelectorAll('.image-thumb-button'));
  let previewIndex = -1;

  if (previewModal) {
    previewModal.hidden = true;
  }

  function showPreviewAt(index) {
    if (!previewModal || !previewImage || !previewCaption || !previewButtons.length) {
      return;
    }
    const normalized = (index + previewButtons.length) % previewButtons.length;
    const button = previewButtons[normalized];
    const src = button.getAttribute('data-preview-src');
    const name = button.getAttribute('data-preview-name') || '';
    previewImage.src = src;
    previewCaption.textContent = name;
    previewModal.hidden = false;
    document.body.classList.add('has-modal-open');
    previewIndex = normalized;
  }

  function closePreview() {
    if (!previewModal) {
      return;
    }
    previewModal.hidden = true;
    document.body.classList.remove('has-modal-open');
    previewImage.src = '';
    previewCaption.textContent = '';
    previewIndex = -1;
  }

  if (previewModal && previewImage && previewCaption && previewClose) {
    previewButtons.forEach((button, idx) => {
      button.addEventListener('click', function () {
        showPreviewAt(idx);
      });
    });

    if (previewPrev) {
      previewPrev.addEventListener('click', function () {
        if (previewIndex === -1) {
          return;
        }
        showPreviewAt(previewIndex - 1);
      });
    }

    if (previewNext) {
      previewNext.addEventListener('click', function () {
        if (previewIndex === -1) {
          return;
        }
        showPreviewAt(previewIndex + 1);
      });
    }

    previewClose.addEventListener('click', closePreview);
    previewModal.addEventListener('click', function (event) {
      if (event.target === previewModal) {
        closePreview();
      }
    });

    window.addEventListener('keydown', function (event) {
      if (event.key === 'Escape') {
        closePreview();
      } else if (event.key === 'ArrowLeft' && previewIndex !== -1) {
        showPreviewAt(previewIndex - 1);
      } else if (event.key === 'ArrowRight' && previewIndex !== -1) {
        showPreviewAt(previewIndex + 1);
      }
    });
  }
})();
