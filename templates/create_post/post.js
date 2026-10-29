document.addEventListener('DOMContentLoaded', function() {
    const dropZone = document.getElementById('dropZone');
    const fileInput = document.getElementById('imageUpload');
    const postContent = document.getElementById('postContent');
    const createPostForm = document.getElementById('createPostForm');
    const contentCounter = document.getElementById('contentCounter');
    const postAction = document.getElementById('postAction');
    const privacyModal = document.getElementById('privacyModal');

    ['dragenter', 'dragover'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.style.borderColor = '#5841f5';
            dropZone.style.backgroundColor = '#eef1ff';
        }, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropZone.addEventListener(eventName, (e) => {
            e.preventDefault();
            e.stopPropagation();
            dropZone.style.borderColor = '#e0e4e8';
            dropZone.style.backgroundColor = '#fafbfc';
        }, false);
    });

    dropZone.addEventListener('drop', (e) => {
        handleFiles(e.dataTransfer.files);
    });

    fileInput.addEventListener('change', function() {
        handleFiles(this.files);
    });

    function handleFiles(files) {
        if (files.length === 0) {
            return;
        }

        const file = files[0];
        dropZone.innerHTML = `
            <i class="fas fa-check-circle" style="color:#4CAF50; font-size:30px;"></i>
            <div>
                <strong>${file.name}</strong>
                <span style="font-size:12px; color:#777;">${(file.size / 1024).toFixed(1)} KB</span>
            </div>
        `;
    }

    postContent.addEventListener('input', function() {
        contentCounter.innerText = `${postContent.value.length} / ${postContent.maxLength}`;
    });
    contentCounter.innerText = `${postContent.value.length} / ${postContent.maxLength}`;

    if (privacyModal) {
        privacyModal.querySelectorAll('[data-action]').forEach((button) => {
            button.addEventListener('click', function() {
                if (button.disabled) {
                    return;
                }
                postAction.value = button.dataset.action;
                createPostForm.submit();
            });
        });

        const editPostBtn = document.getElementById('editPostBtn');
        const cancelModalBtn = document.getElementById('cancelModalBtn');
        const chooseAnotherImageBtn = document.getElementById('chooseAnotherImageBtn');

        editPostBtn.addEventListener('click', function() {
            privacyModal.classList.remove('is-visible');
            postContent.focus();
        });

        cancelModalBtn.addEventListener('click', function() {
            privacyModal.classList.remove('is-visible');
        });

        if (chooseAnotherImageBtn) {
            chooseAnotherImageBtn.addEventListener('click', function() {
                privacyModal.classList.remove('is-visible');
                fileInput.click();
            });
        }
    }

    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', function() {
            navItems.forEach(nav => nav.classList.remove('active'));
            this.classList.add('active');
        });
    });
});
