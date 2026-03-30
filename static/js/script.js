document.addEventListener("DOMContentLoaded", () => {
  // Initialize page animations
  initPageAnimations();
  
  // Analysis progress steps configuration
  const analysisSteps = [
    {
      id: 'upload',
      title: 'Uploading File',
      description: 'Securely uploading your email file...',
      icon: 'fas fa-upload',
      duration: 1000
    },
    {
      id: 'parsing',
      title: 'Parsing Email',
      description: 'Extracting email structure and metadata...',
      icon: 'fas fa-cogs',
      duration: 1500
    },
    {
      id: 'headers',
      title: 'Analyzing Headers',
      description: 'Checking authentication and routing information...',
      icon: 'fas fa-envelope-open',
      duration: 2000
    },
    {
      id: 'content',
      title: 'Analyzing Content',
      description: 'Scanning for suspicious patterns and keywords...',
      icon: 'fas fa-file-alt',
      duration: 2500
    },
    {
      id: 'urls',
      title: 'Analyzing URLs',
      description: 'Checking links for malicious indicators...',
      icon: 'fas fa-link',
      duration: 2000
    },
    {
      id: 'attachments',
      title: 'Analyzing Attachments',
      description: 'Scanning files for potential threats...',
      icon: 'fas fa-paperclip',
      duration: 1800
    },
    {
      id: 'verdict',
      title: 'Generating Report',
      description: 'Calculating risk score and final verdict...',
      icon: 'fas fa-gavel',
      duration: 1000
    }
  ];

  // Initialize page animations
  function initPageAnimations() {
    // Animate cards on page load
    const cards = document.querySelectorAll('.card');
    cards.forEach((card, index) => {
      card.style.animationDelay = `${index * 0.1}s`;
    });

    // Initialize intersection observer for scroll animations
    const observerOptions = {
      threshold: 0.1,
      rootMargin: '0px 0px -50px 0px'
    };

    const observer = new IntersectionObserver((entries) => {
      entries.forEach(entry => {
        if (entry.isIntersecting) {
          entry.target.classList.add('animate-in');
        }
      });
    }, observerOptions);

    // Observe elements for scroll animations
    document.querySelectorAll('.card, .alert, .badge').forEach(el => {
      observer.observe(el);
    });
  }

  // Initialize analysis progress overlay
  function initProgressOverlay() {
    const progressHTML = `
      <div class="analysis-progress" id="analysisProgress">
        <div class="progress-container">
          <div class="mb-4">
            <h3 class="text-center mb-3">Analyzing Email</h3>
            <div class="progress-bar-container">
              <div class="progress-bar" id="progressBar" style="width: 0%"></div>
            </div>
          </div>
          
          <div class="progress-steps" id="progressSteps">
            ${analysisSteps.map(step => `
              <div class="progress-step" data-step="${step.id}">
                <div class="progress-icon">
                  <i class="${step.icon}"></i>
                </div>
                <div class="progress-text">
                  <div class="progress-title">${step.title}</div>
                  <div class="progress-description">${step.description}</div>
                </div>
              </div>
            `).join('')}
          </div>
          
          <div class="text-center">
            <p class="text-muted mb-0">Please wait while we analyze your email...</p>
          </div>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', progressHTML);
  }

  // Show progress overlay with animations
  function showProgressOverlay() {
    const overlay = document.getElementById('analysisProgress');
    if (overlay) {
      overlay.classList.add('show');
      // Animate progress container
      const container = overlay.querySelector('.progress-container');
      container.style.transform = 'scale(0.8)';
      container.style.opacity = '0';
      
      setTimeout(() => {
        container.style.transition = 'all 0.3s ease';
        container.style.transform = 'scale(1)';
        container.style.opacity = '1';
        startProgressAnimation();
      }, 100);
    }
  }

  // Start the step-by-step progress animation
  function startProgressAnimation() {
    let currentStep = 0;
    let totalProgress = 0;
    
    function animateStep() {
      if (currentStep >= analysisSteps.length) {
        return;
      }
      
      const step = analysisSteps[currentStep];
      const stepElement = document.querySelector(`[data-step="${step.id}"]`);
      const progressBar = document.getElementById('progressBar');
      
      // Mark current step as active with animation
      stepElement.classList.add('active');
      stepElement.style.transform = 'scale(1.02)';
      
      // Animate progress bar
      const stepProgress = (100 / analysisSteps.length);
      totalProgress += stepProgress;
      progressBar.style.width = `${Math.min(totalProgress, 100)}%`;
      
      // Complete current step after duration
      setTimeout(() => {
        stepElement.classList.remove('active');
        stepElement.classList.add('completed');
        stepElement.style.transform = 'scale(1)';
        
        // Add check icon to completed step with animation
        const icon = stepElement.querySelector('.progress-icon i');
        icon.className = 'fas fa-check';
        
        // Add checkmark animation
        const iconContainer = stepElement.querySelector('.progress-icon');
        iconContainer.innerHTML = '<div class="checkmark"></div>';
        
        currentStep++;
        
        if (currentStep < analysisSteps.length) {
          setTimeout(animateStep, 200); // Small delay between steps
        } else {
          // All steps completed
          progressBar.style.width = '100%';
          setTimeout(() => {
            showCompletionAnimation();
          }, 500);
        }
      }, step.duration);
    }
    
    // Start the animation after a brief delay
    setTimeout(animateStep, 500);
  }

  // Show completion animation
  function showCompletionAnimation() {
    const container = document.querySelector('.progress-container');
    const completionMessage = document.createElement('div');
    completionMessage.className = 'text-center mt-4';
    completionMessage.innerHTML = `
      <div class="checkmark mx-auto mb-3"></div>
      <h4 class="text-success">Analysis Complete!</h4>
      <p class="text-muted">Redirecting to results...</p>
    `;
    container.appendChild(completionMessage);
  }

  // Enhanced file upload functionality
  const uploadForm = document.querySelector('form[enctype="multipart/form-data"]');
  if (uploadForm) {
    const fileInput = document.getElementById("emailFile");
    const submitButton = uploadForm.querySelector('button[type="submit"]');
    const originalButtonText = submitButton.innerHTML;
    const fileUploadWrapper = fileInput.closest('.file-upload-wrapper');

    // Enhanced drag and drop with animations
    if (fileUploadWrapper) {
      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        fileUploadWrapper.addEventListener(eventName, preventDefaults, false);
      });

      function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
      }

      fileUploadWrapper.addEventListener('dragenter', () => {
        fileUploadWrapper.classList.add('drag-over');
      });

      fileUploadWrapper.addEventListener('dragleave', (e) => {
        if (!fileUploadWrapper.contains(e.relatedTarget)) {
          fileUploadWrapper.classList.remove('drag-over');
        }
      });

      fileUploadWrapper.addEventListener('drop', (e) => {
        fileUploadWrapper.classList.remove('drag-over');
        const files = e.dataTransfer.files;
        if (files.length > 0) {
          fileInput.files = files;
          handleFileSelection(files[0]);
        }
      });
    }

    // File selection handler with animations
    fileInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) {
        handleFileSelection(file);
      }
    });

    function handleFileSelection(file) {
      // Reset any previous error states
      fileInput.classList.remove('error');
      
      // Validate file size
      const maxSize = 10 * 1024 * 1024; // 10MB
      if (file.size > maxSize) {
        showAlert("File size must be less than 10MB", "warning");
        fileInput.value = "";
        fileInput.classList.add('error');
        return false;
      }

      // Validate file type
      const allowedTypes = [".eml", ".msg"];
      const fileExtension = "." + file.name.split(".").pop().toLowerCase();
      if (!allowedTypes.includes(fileExtension)) {
        showAlert("Please select a valid email file (.eml or .msg)", "warning");
        fileInput.value = "";
        fileInput.classList.add('error');
        return false;
      }

      // Show success feedback with animation
      showFileInfo(file);
      
      // Animate the input to show success
      fileInput.style.borderColor = 'var(--success)';
      fileInput.style.backgroundColor = 'rgba(16, 185, 129, 0.05)';
      
      return true;
    }

    // Enhanced form submission
    uploadForm.addEventListener("submit", (e) => {
      if (fileInput.files.length === 0) {
        e.preventDefault();
        showAlert("Please select a file to upload", "warning");
        fileInput.classList.add('error');
        return false;
      }

      const file = fileInput.files[0];
      if (!handleFileSelection(file)) {
        e.preventDefault();
        return false;
      }

      // Animate button to loading state
      submitButton.disabled = true;
      submitButton.classList.add('loading');
      submitButton.style.width = submitButton.offsetWidth + 'px'; // Prevent width change
      submitButton.innerHTML = 'Starting Analysis...';

      // Initialize and show progress overlay
      initProgressOverlay();
      setTimeout(() => {
        showProgressOverlay();
      }, 200);
    });
  }

  // Enhanced alert system with animations
  function showAlert(message, type = "info", duration = 5000) {
    const alertContainer = document.querySelector(".container-fluid .row .col-12") || document.body;
    const alertId = 'alert-' + Date.now();
    
    const alert = document.createElement("div");
    alert.id = alertId;
    alert.className = `alert alert-${type} alert-dismissible`;
    alert.innerHTML = `
      <i class="fas fa-${getAlertIcon(type)} me-2"></i>${message}
      <button type="button" class="btn-close" onclick="this.parentElement.remove()" aria-label="Close">×</button>
    `;

    alertContainer.insertBefore(alert, alertContainer.firstChild);

    // Auto-dismiss with animation
    if (duration > 0) {
      setTimeout(() => {
        if (document.getElementById(alertId)) {
          alert.classList.add('fade-out');
          setTimeout(() => alert.remove(), 300);
        }
      }, duration);
    }

    return alert;
  }

  function getAlertIcon(type) {
    const icons = {
      info: "info-circle",
      warning: "exclamation-triangle",
      success: "check-circle",
      danger: "exclamation-circle",
    };
    return icons[type] || "info-circle";
  }

  function showFileInfo(file) {
    const fileSize = (file.size / 1024).toFixed(2);
    const message = `File selected: ${file.name} (${fileSize} KB)`;
    showAlert(message, "success", 3000);
  }

  // Enhanced URL copying with animations
  document.addEventListener('click', (e) => {
    const urlElement = e.target.closest('[data-url], .url-copy');
    if (urlElement) {
      e.preventDefault();
      const url = urlElement.getAttribute('data-url') || urlElement.textContent.trim();
      
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(url)
          .then(() => {
            showCopySuccess(urlElement);
            showAlert("URL copied to clipboard!", "success", 2000);
          })
          .catch(() => {
            fallbackCopyText(url);
          });
      } else {
        fallbackCopyText(url);
      }
    }
  });

  function showCopySuccess(element) {
    const originalContent = element.innerHTML;
    const originalBg = element.style.backgroundColor;
    
    element.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
    element.style.backgroundColor = 'var(--success)';
    element.style.color = 'white';
    element.style.transform = 'scale(1.05)';
    
    setTimeout(() => {
      element.style.transform = 'scale(1)';
      setTimeout(() => {
        element.innerHTML = originalContent;
        element.style.backgroundColor = originalBg;
        element.style.color = '';
      }, 200);
    }, 100);
  }

  function fallbackCopyText(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    document.body.appendChild(textArea);
    textArea.select();

    try {
      document.execCommand("copy");
      showAlert("URL copied to clipboard!", "success", 2000);
    } catch (err) {
      showAlert("Could not copy URL. Please copy manually.", "warning");
    }

    document.body.removeChild(textArea);
  }

  // Enhanced button interactions
  document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('mouseenter', function() {
      if (!this.disabled && !this.classList.contains('loading')) {
        this.style.transform = 'translateY(-2px)';
      }
    });
    
    button.addEventListener('mouseleave', function() {
      if (!this.disabled && !this.classList.contains('loading')) {
        this.style.transform = 'translateY(0)';
      }
    });

    button.addEventListener('click', function() {
      if (this.href || this.type === 'submit') {
        this.style.transform = 'scale(0.98)';
        setTimeout(() => {
          this.style.transform = '';
        }, 150);
      }
    });
  });

  // Enhanced table row animations
  document.querySelectorAll('.table tbody tr').forEach(row => {
    row.addEventListener('mouseenter', function() {
      this.style.transform = 'translateX(5px)';
    });
    
    row.addEventListener('mouseleave', function() {
      this.style.transform = 'translateX(0)';
    });
  });

  // Mobile navigation enhancements
  const navbarToggler = document.querySelector(".navbar-toggler");
  const navbarCollapse = document.querySelector(".navbar-collapse");

  if (navbarToggler && navbarCollapse) {
    navbarToggler.addEventListener('click', function() {
      this.style.transform = 'rotate(90deg)';
      setTimeout(() => {
        this.style.transform = 'rotate(0deg)';
      }, 200);
    });
  }

  // Smooth scroll for anchor links
  document.querySelectorAll('a[href^="#"]').forEach(anchor => {
    anchor.addEventListener('click', function(e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute('href'));
      if (target) {
        target.scrollIntoView({
          behavior: 'smooth',
          block: 'start'
        });
      }
    });
  });

  // Add subtle entrance animations to existing elements
  setTimeout(() => {
    document.querySelectorAll('.card, .alert, .badge').forEach((el, index) => {
      el.style.opacity = '1';
      el.style.transform = 'translateY(0)';
    });
  }, 100);
});

  // Initialize analysis progress overlay
  function initProgressOverlay() {
    const progressHTML = `
      <div class="analysis-progress" id="analysisProgress">
        <div class="progress-container">
          <div class="mb-4">
            <h3 class="text-center mb-3">Analyzing Email</h3>
            <div class="progress-bar-container">
              <div class="progress-bar" id="progressBar" style="width: 0%"></div>
            </div>
          </div>
          
          <div class="progress-steps" id="progressSteps">
            ${analysisSteps.map(step => `
              <div class="progress-step" data-step="${step.id}">
                <div class="progress-icon">
                  <i class="${step.icon}"></i>
                </div>
                <div class="progress-text">
                  <div class="progress-title">${step.title}</div>
                  <div class="progress-description">${step.description}</div>
                </div>
              </div>
            `).join('')}
          </div>
          
          <div class="text-center">
            <p class="text-muted mb-0">Please wait while we analyze your email...</p>
          </div>
        </div>
      </div>
    `;
    
    document.body.insertAdjacentHTML('beforeend', progressHTML);
  }

  // Show progress overlay with animations
  function showProgressOverlay() {
    const overlay = document.getElementById('analysisProgress');
    if (overlay) {
      overlay.classList.add('show');
      startProgressAnimation();
    }
  }

  // Hide progress overlay
  function hideProgressOverlay() {
    const overlay = document.getElementById('analysisProgress');
    if (overlay) {
      overlay.classList.remove('show');
      setTimeout(() => overlay.remove(), 300);
    }
  }

  // Start the step-by-step progress animation
  function startProgressAnimation() {
    let currentStep = 0;
    let totalProgress = 0;
    
    function handleFileSelection(file) {
      // Validate file size (10MB limit)
      const maxSize = 10 * 1024 * 1024; // 10MB
      if (file.size > maxSize) {
        showAlert("File size must be less than 10MB", "warning");
        fileInput.value = "";
        return false;
      }

      // Validate file type
      const allowedTypes = [".eml", ".msg"];
      const fileExtension = "." + file.name.split(".").pop().toLowerCase();
      if (!allowedTypes.includes(fileExtension)) {
        showAlert("Please select a valid email file (.eml or .msg)", "warning");
        fileInput.value = "";
        return false;
      }

      // Show file info with enhanced animation
      showFileInfo(file);
      return true;
    }

    // Enhanced form submission with progress overlay
    uploadForm.addEventListener("submit", (e) => {
      if (fileInput.files.length === 0) {
        e.preventDefault();
        showAlert("Please select a file to upload", "warning");
        return false;
      }

      const file = fileInput.files[0];
      if (!handleFileSelection(file)) {
        e.preventDefault();
        return false;
      }

      // Show loading state on button
      submitButton.disabled = true;
      submitButton.classList.add('loading');
      submitButton.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Starting Analysis...';

      // Initialize and show progress overlay
      initProgressOverlay();
      setTimeout(() => {
        showProgressOverlay();
      }, 100);

      // Note: The progress animation will run while the server processes the file
      // The server should redirect to results page when complete
    });
  }

  // Enhanced alert system with better animations
  function showAlert(message, type = "info", duration = 5000) {
    const alertContainer = document.querySelector(".container-fluid .row .col-12") || document.body;
    const alertId = 'alert-' + Date.now();
    
    const alert = document.createElement("div");
    alert.id = alertId;
    alert.className = `alert alert-${type} alert-dismissible fade show mt-3`;
    alert.style.opacity = '0';
    alert.style.transform = 'translateY(-20px)';
    alert.innerHTML = `
      <i class="fas fa-${getAlertIcon(type)} me-2"></i>${message}
      <button type="button" class="btn-close" data-bs-dismiss="alert" aria-label="Close"></button>
    `;

    alertContainer.insertBefore(alert, alertContainer.firstChild);

    // Animate in
    setTimeout(() => {
      alert.style.transition = 'all 0.3s ease';
      alert.style.opacity = '1';
      alert.style.transform = 'translateY(0)';
    }, 10);

    // Auto-dismiss
    if (duration > 0) {
      setTimeout(() => {
        if (document.getElementById(alertId)) {
          fadeOut(alert);
        }
      }, duration);
    }

    return alert;
  }

  function getAlertIcon(type) {
    const icons = {
      info: "info-circle",
      warning: "exclamation-triangle",
      success: "check-circle",
      danger: "exclamation-circle",
    };
    return icons[type] || "info-circle";
  }

  function showFileInfo(file) {
    const fileSize = (file.size / 1024).toFixed(2);
    const message = `Selected: ${file.name} (${fileSize} KB)`;
    showAlert(message, "success");
  }

  // Enhanced URL copying functionality
  document.addEventListener('click', (e) => {
    const urlElement = e.target.closest('[data-url]');
    if (urlElement) {
      e.preventDefault();
      const url = urlElement.getAttribute('data-url') || urlElement.textContent.trim();
      
      if (navigator.clipboard && window.isSecureContext) {
        navigator.clipboard.writeText(url)
          .then(() => {
            showCopySuccess(urlElement);
            showAlert("URL copied to clipboard!", "success", 2000);
          })
          .catch(() => {
            fallbackCopyText(url);
          });
      } else {
        fallbackCopyText(url);
      }
    }
  });

  function showCopySuccess(element) {
    const originalContent = element.innerHTML;
    const originalClasses = element.className;
    
    element.innerHTML = '<i class="fas fa-check me-1"></i>Copied!';
    element.classList.add('text-success');
    
    setTimeout(() => {
      element.innerHTML = originalContent;
      element.className = originalClasses;
    }, 2000);
  }

  function fallbackCopyText(text) {
    const textArea = document.createElement("textarea");
    textArea.value = text;
    textArea.style.position = "fixed";
    textArea.style.left = "-999999px";
    textArea.style.top = "-999999px";
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();

    try {
      document.execCommand("copy");
      showAlert("URL copied to clipboard!", "success", 2000);
    } catch (err) {
      showAlert("Could not copy URL. Please copy manually.", "warning");
    }

    document.body.removeChild(textArea);
  }

  // Enhanced mobile navigation
  const navbarToggler = document.querySelector(".navbar-toggler");
  const navbarCollapse = document.querySelector(".navbar-collapse");

  if (navbarToggler && navbarCollapse) {
    // Close mobile menu when clicking outside
    document.addEventListener("click", (e) => {
      if (!navbarToggler.contains(e.target) && !navbarCollapse.contains(e.target)) {
        if (navbarCollapse.classList.contains("show")) {
          navbarToggler.click();
        }
      }
    });

    // Close mobile menu when clicking nav links
    const navLinks = navbarCollapse.querySelectorAll(".nav-link");
    navLinks.forEach((link) => {
      link.addEventListener("click", () => {
        if (navbarCollapse.classList.contains("show")) {
          navbarToggler.click();
        }
      });
    });
  }

  // Enhanced card animations on scroll
  const observerOptions = {
    threshold: 0.1,
    rootMargin: '0px 0px -50px 0px'
  };

  const observer = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        entry.target.style.opacity = '1';
        entry.target.style.transform = 'translateY(0)';
      }
    });
  }, observerOptions);

  // Observe cards for scroll animations
  document.querySelectorAll('.card').forEach((card, index) => {
    card.style.opacity = '0';
    card.style.transform = 'translateY(30px)';
    card.style.transition = `opacity 0.6s ease ${index * 0.1}s, transform 0.6s ease ${index * 0.1}s`;
    observer.observe(card);
  });

  // Enhanced table interactions for mobile
  const tables = document.querySelectorAll(".table-responsive table");
  tables.forEach((table) => {
    const rows = table.querySelectorAll("tbody tr");
    rows.forEach((row) => {
      // Add touch-friendly row highlighting
      row.addEventListener("touchstart", function () {
        this.style.backgroundColor = "rgba(102, 126, 234, 0.1)";
      });

      row.addEventListener("touchend", function () {
        setTimeout(() => {
          this.style.backgroundColor = "";
        }, 150);
      });

      // Enhanced hover effects
      row.addEventListener("mouseenter", function () {
        this.style.transform = "scale(1.01)";
        this.style.boxShadow = "0 2px 8px rgba(0,0,0,0.1)";
      });

      row.addEventListener("mouseleave", function () {
        this.style.transform = "scale(1)";
        this.style.boxShadow = "none";
      });
    });
  });

  // Smooth scrolling for anchor links
  document.querySelectorAll('a[href^="#"]').forEach((anchor) => {
    anchor.addEventListener("click", function (e) {
      e.preventDefault();
      const target = document.querySelector(this.getAttribute("href"));
      if (target) {
        target.scrollIntoView({
          behavior: "smooth",
          block: "start",
        });
      }
    });
  });

  // Enhanced button hover effects
  document.querySelectorAll('.btn').forEach(button => {
    button.addEventListener('mouseenter', function() {
      this.style.transform = 'translateY(-2px)';
    });
    
    button.addEventListener('mouseleave', function() {
      if (!this.classList.contains('loading')) {
        this.style.transform = 'translateY(0)';
      }
    });
  });

  // Utility function for fade out animations
  function fadeOut(element) {
    element.style.transition = "opacity 0.5s ease, transform 0.5s ease";
    element.style.opacity = "0";
    element.style.transform = "translateY(-20px)";
    setTimeout(() => {
      if (element.parentNode) {
        element.parentNode.removeChild(element);
      }
    }, 500);
  }

  // Add keyboard navigation support
  document.addEventListener("keydown", (e) => {
    // ESC key to close modals/dropdowns/overlays
    if (e.key === "Escape") {
      // Close analysis progress overlay
      const progressOverlay = document.getElementById('analysisProgress');
      if (progressOverlay && progressOverlay.classList.contains('show')) {
        hideProgressOverlay();
      }

      // Close dropdowns
      const openDropdowns = document.querySelectorAll(".dropdown-menu.show");
      openDropdowns.forEach((dropdown) => {
        dropdown.classList.remove("show");
      });

      // Close mobile navigation
      const openCollapses = document.querySelectorAll(".navbar-collapse.show");
      openCollapses.forEach((collapse) => {
        const toggler = document.querySelector(".navbar-toggler");
        if (toggler) toggler.click();
      });
    }
  });

  // Performance optimization: Lazy load images if any
  if ("IntersectionObserver" in window) {
    const imageObserver = new IntersectionObserver((entries, observer) => {
      entries.forEach((entry) => {
        if (entry.isIntersecting) {
          const img = entry.target;
          img.src = img.dataset.src;
          img.classList.remove("lazy");
          imageObserver.unobserve(img);
        }
      });
    });

    document.querySelectorAll("img[data-src]").forEach((img) => {
      imageObserver.observe(img);
    });
  }

  // Add loading states to action buttons
  document.querySelectorAll('a[href*="analyze"], a[href*="upload"]').forEach(link => {
    link.addEventListener('click', function() {
      if (!this.classList.contains('btn-outline-secondary')) {
        this.classList.add('loading');
        const originalText = this.innerHTML;
        this.innerHTML = '<i class="fas fa-spinner fa-spin me-2"></i>Loading...';
        
        // Reset after a delay if navigation doesn't happen
        setTimeout(() => {
          if (this.classList.contains('loading')) {
            this.classList.remove('loading');
            this.innerHTML = originalText;
          }
        }, 5000);
      }
    });
  });

  // Initialize page animations
  setTimeout(() => {
    document.body.classList.add('page-loaded');
  }, 100);

  // Add custom CSS for drag and drop
  const dragDropCSS = `
    .file-upload-wrapper.drag-over .form-control {
      border-color: var(--primary) !important;
      background: rgba(102, 126, 234, 0.1) !important;
      transform: scale(1.02);
    }
    
    .page-loaded .card {
      animation: slideUp 0.6s ease forwards;
    }
    
    .page-loaded .card:nth-child(1) { animation-delay: 0s; }
    .page-loaded .card:nth-child(2) { animation-delay: 0.1s; }
    .page-loaded .card:nth-child(3) { animation-delay: 0.2s; }
    .page-loaded .card:nth-child(4) { animation-delay: 0.3s; }
  `;
  
  const style = document.createElement('style');
  style.textContent = dragDropCSS;
  document.head.appendChild(style);
; animateStep() 
      if (currentStep >= analysisSteps.length) {
        return;
      }
      
      const step = analysisSteps[currentStep];
      const stepElement = document.querySelector(`[data-step="${step.id}"]`);
      const progressBar = document.getElementById('progressBar');
      
      // Mark current step as active
      stepElement.classList.add('active');
      
      // Animate progress bar
      const stepProgress = (100 / analysisSteps.length);
      totalProgress += stepProgress;
      progressBar.style.width = `${Math.min(totalProgress, 100)}%`;
      
      // Complete current step after duration
      setTimeout(() => {
        stepElement.classList.remove('active');
        stepElement.classList.add('completed');
        
        // Add check icon to completed step
        const icon = stepElement.querySelector('.progress-icon i');
        icon.className = 'fas fa-check';
        
        currentStep++;
        
        if (currentStep < analysisSteps.length) {
          animateStep();
        } else {
          // All steps completed, redirect will happen from server
          progressBar.style.width = '100%';
        }
      }, step.duration);
    
    
    // Start the animation
    setTimeout(animateStep, 500);
    

  // Enhanced file upload with progress tracking
  const uploadForm = document.querySelector('form[enctype="multipart/form-data"]');
  if (uploadForm) {
    const fileInput = document.getElementById("emailFile");
    const submitButton = uploadForm.querySelector('button[type="submit"]');
    const originalButtonText = submitButton.innerHTML;

    // File drag and drop enhancement
    const fileUploadWrapper = document.querySelector('.file-upload-wrapper');
    if (fileUploadWrapper) {
      ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        fileUploadWrapper.addEventListener(eventName, preventDefaults, false);
      });

      function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
      }

      ['dragenter', 'dragover'].forEach(eventName => {
        fileUploadWrapper.addEventListener(eventName, highlight, false);
      });

      ['dragleave', 'drop'].forEach(eventName => {
        fileUploadWrapper.addEventListener(eventName, unhighlight, false);
      });

      function highlight(e) {
        fileUploadWrapper.classList.add('drag-over');
      }

      function unhighlight(e) {
        fileUploadWrapper.classList.remove('drag-over');
      }

      fileUploadWrapper.addEventListener('drop', handleDrop, false);

      function handleDrop(e) {
        const dt = e.dataTransfer;
        const files = dt.files;
        
        if (files.length > 0) {
          fileInput.files = files;
          handleFileSelection(files[0]);
        }
      }
    }

    // Enhanced file validation and preview
    fileInput.addEventListener("change", (e) => {
      const file = e.target.files[0];
      if (file) {
        handleFileSelection(file);
      }
    });

  }