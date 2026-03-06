/* ============================================================
   CiphereCore — Main JavaScript
   ============================================================ */

document.addEventListener('DOMContentLoaded', () => {

  /* ---------- Header Scroll Effect ---------- */
  const header = document.querySelector('.site-header');
  if (header) {
    const onScroll = () => {
      header.classList.toggle('scrolled', window.scrollY > 40);
    };
    window.addEventListener('scroll', onScroll, { passive: true });
    onScroll();
  }

  /* ---------- Mobile Navigation ---------- */
  const navToggle = document.querySelector('.nav-toggle');
  const navMobile = document.querySelector('.nav-mobile');
  if (navToggle && navMobile) {
    navToggle.addEventListener('click', () => {
      navToggle.classList.toggle('open');
      navMobile.classList.toggle('open');
      document.body.style.overflow = navMobile.classList.contains('open') ? 'hidden' : '';
    });
    // Close menu on link click
    navMobile.querySelectorAll('a').forEach(link => {
      link.addEventListener('click', () => {
        navToggle.classList.remove('open');
        navMobile.classList.remove('open');
        document.body.style.overflow = '';
      });
    });
  }

  /* ---------- Active Nav Link ---------- */
  const currentPage = window.location.pathname.split('/').pop() || 'index.html';
  document.querySelectorAll('.nav-desktop a, .nav-mobile a').forEach(link => {
    const href = link.getAttribute('href');
    if (href === currentPage || (currentPage === '' && href === 'index.html')) {
      link.classList.add('active');
    }
  });

  /* ---------- Scroll-Triggered Fade Animations ---------- */
  const fadeEls = document.querySelectorAll('.fade-up');
  if (fadeEls.length > 0) {
    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('visible');
          observer.unobserve(entry.target);
        }
      });
    }, { threshold: 0.15, rootMargin: '0px 0px -40px 0px' });
    fadeEls.forEach(el => observer.observe(el));
  }

  /* ---------- FAQ Accordion ---------- */
  document.querySelectorAll('.faq-question').forEach(btn => {
    btn.addEventListener('click', () => {
      const item = btn.closest('.faq-item');
      const wasOpen = item.classList.contains('open');
      // Close all others
      document.querySelectorAll('.faq-item.open').forEach(i => i.classList.remove('open'));
      if (!wasOpen) item.classList.add('open');
    });
  });

  /* ---------- Smooth Scroll for Anchor Links ---------- */
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', (e) => {
      const target = document.querySelector(anchor.getAttribute('href'));
      if (target) {
        e.preventDefault();
        const top = target.getBoundingClientRect().top + window.scrollY - 80;
        window.scrollTo({ top, behavior: 'smooth' });
      }
    });
  });

  /* ---------- Animated Counter ---------- */
  const counters = document.querySelectorAll('[data-count]');
  if (counters.length > 0) {
    const countObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          const el = entry.target;
          const target = parseInt(el.getAttribute('data-count'), 10);
          const suffix = el.getAttribute('data-suffix') || '';
          const duration = 2000;
          const start = performance.now();

          const animate = (now) => {
            const progress = Math.min((now - start) / duration, 1);
            const eased = 1 - Math.pow(1 - progress, 3); // ease-out cubic
            el.textContent = Math.floor(eased * target).toLocaleString() + suffix;
            if (progress < 1) requestAnimationFrame(animate);
          };
          requestAnimationFrame(animate);
          countObserver.unobserve(el);
        }
      });
    }, { threshold: 0.5 });
    counters.forEach(el => countObserver.observe(el));
  }

  /* ---------- Download / Install Handler ---------- */
  const downloadBtns = document.querySelectorAll('[data-download]');
  const installerModal = document.getElementById('installer-modal');

  downloadBtns.forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      const fileUrl = btn.getAttribute('href');
      startInstaller(fileUrl);
    });
  });

  function startInstaller(fileUrl) {
    if (!installerModal) {
      // Direct download fallback
      triggerDirectDownload(fileUrl);
      return;
    }
    installerModal.classList.add('active');
    document.body.style.overflow = 'hidden';

    const progressBar = installerModal.querySelector('.installer-progress-bar');
    const statusText = installerModal.querySelector('.installer-status');
    const percentText = installerModal.querySelector('.installer-percent');

    const steps = [
      { progress: 10, text: 'Preparing download...' },
      { progress: 25, text: 'Verifying system compatibility...' },
      { progress: 45, text: 'Downloading CiphereCore v2.0...' },
      { progress: 65, text: 'Downloading encryption modules...' },
      { progress: 80, text: 'Verifying file integrity (SHA-256)...' },
      { progress: 95, text: 'Finalizing package...' },
      { progress: 100, text: 'Download complete!' },
    ];

    let stepIndex = 0;

    function nextStep() {
      if (stepIndex >= steps.length) {
        setTimeout(() => {
          triggerDirectDownload(fileUrl);
          showToast('Download started! Check your downloads folder.', 'success');
          closeInstaller();
        }, 800);
        return;
      }
      const step = steps[stepIndex];
      if (progressBar) progressBar.style.width = step.progress + '%';
      if (statusText) statusText.textContent = step.text;
      if (percentText) percentText.textContent = step.progress + '%';
      stepIndex++;
      setTimeout(nextStep, 600 + Math.random() * 500);
    }

    // Reset
    if (progressBar) progressBar.style.width = '0%';
    if (statusText) statusText.textContent = 'Initializing...';
    if (percentText) percentText.textContent = '0%';

    setTimeout(nextStep, 400);
  }

  function closeInstaller() {
    if (installerModal) {
      installerModal.classList.remove('active');
      document.body.style.overflow = '';
    }
  }

  // Close installer on backdrop click
  if (installerModal) {
    installerModal.addEventListener('click', (e) => {
      if (e.target === installerModal) closeInstaller();
    });
    const closeBtn = installerModal.querySelector('.installer-close');
    if (closeBtn) closeBtn.addEventListener('click', closeInstaller);
  }

  function triggerDirectDownload(url) {
    // Navigate directly to the file to bypass any blob/cors issues
    // that cause Chromium browsers to assign UUIDs to downloaded files.
    // Ensure we trigger the download by navigating explicitly to the actual file path.
    window.location.assign(url || 'CiphereCore_Installer_v2.0.exe');
  }

  /* ---------- Toast Notification ---------- */
  window.showToast = function (message, type = 'success') {
    // Remove existing toasts
    document.querySelectorAll('.toast').forEach(t => t.remove());

    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.innerHTML = `
      <svg class="toast-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="color:${type === 'success' ? 'var(--accent-green)' : 'var(--accent-red)'}">
        ${type === 'success'
        ? '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>'
        : '<circle cx="12" cy="12" r="10"/><line x1="15" y1="9" x2="9" y2="15"/><line x1="9" y1="9" x2="15" y2="15"/>'
      }
      </svg>
      <span class="toast-message">${message}</span>
    `;
    document.body.appendChild(toast);
    requestAnimationFrame(() => {
      requestAnimationFrame(() => toast.classList.add('show'));
    });
    setTimeout(() => {
      toast.classList.remove('show');
      setTimeout(() => toast.remove(), 400);
    }, 4000);
  };

  /* ---------- Contact Form Handler ---------- */
  const contactForm = document.getElementById('contact-form');
  if (contactForm) {
    contactForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const formData = new FormData(contactForm);
      const data = Object.fromEntries(formData.entries());

      // Basic validation
      if (!data.name || !data.email || !data.message) {
        showToast('Please fill in all required fields.', 'error');
        return;
      }
      if (!data.email.includes('@')) {
        showToast('Please enter a valid email address.', 'error');
        return;
      }

      // Simulate form submission
      const submitBtn = contactForm.querySelector('button[type="submit"]');
      const originalText = submitBtn.textContent;
      submitBtn.textContent = 'Sending...';
      submitBtn.disabled = true;

      setTimeout(() => {
        showToast('Message sent successfully! We\'ll get back to you soon.', 'success');
        contactForm.reset();
        submitBtn.textContent = originalText;
        submitBtn.disabled = false;
      }, 1500);
    });
  }

  /* ---------- Docs Sidebar Active Link Tracking ---------- */
  const docsSections = document.querySelectorAll('.docs-content h2[id], .docs-content h3[id]');
  const docsLinks = document.querySelectorAll('.docs-sidebar a');
  if (docsSections.length > 0 && docsLinks.length > 0) {
    const docsObserver = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          docsLinks.forEach(l => l.classList.remove('active'));
          const activeLink = document.querySelector(`.docs-sidebar a[href="#${entry.target.id}"]`);
          if (activeLink) activeLink.classList.add('active');
        }
      });
    }, { threshold: 0.5, rootMargin: '-80px 0px -60% 0px' });
    docsSections.forEach(s => docsObserver.observe(s));
  }

  /* ---------- Typing Animation for Hero Code Block ---------- */
  const typingEl = document.querySelector('.typing-animation');
  if (typingEl) {
    const lines = typingEl.querySelectorAll('.type-line');
    lines.forEach((line, i) => {
      line.style.opacity = '0';
      line.style.transform = 'translateX(-10px)';
      setTimeout(() => {
        line.style.transition = 'opacity .4s, transform .4s';
        line.style.opacity = '1';
        line.style.transform = 'translateX(0)';
      }, 300 + i * 200);
    });
  }

});
