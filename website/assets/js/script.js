// ============================================
// CIPHERCORE - Interactive Script
// ============================================

document.addEventListener('DOMContentLoaded', () => {
    initScrollAnimations();
    initSmoothScroll();
    initCounterAnimation();
    initNavbarScroll();
});

// ============================================
// Scroll Animations
// ============================================

function initScrollAnimations() {
    const elements = document.querySelectorAll('.feature-card, .security-text, .download-card');
    
    const observer = new IntersectionObserver((entries) => {
        entries.forEach((entry, index) => {
            if (entry.isIntersecting) {
                setTimeout(() => {
                    entry.target.style.animation = `fadeInUp 0.6s ease-out forwards`;
                }, index * 100);
                observer.unobserve(entry.target);
            }
        });
    }, { threshold: 0.1 });
    
    elements.forEach(element => observer.observe(element));
}

// ============================================
// Smooth Scroll
// ============================================

function initSmoothScroll() {
    document.querySelectorAll('a[href^="#"]').forEach(anchor => {
        anchor.addEventListener('click', function (e) {
            e.preventDefault();
            const target = document.querySelector(this.getAttribute('href'));
            if (target) {
                target.scrollIntoView({ behavior: 'smooth' });
            }
        });
    });
}

// ============================================
// Counter Animation
// ============================================

function initCounterAnimation() {
    // Can be extended for statistics
}

// ============================================
// Navbar Scroll Effect
// ============================================

function initNavbarScroll() {
    const navbar = document.querySelector('.navbar');
    let lastScroll = 0;
    
    window.addEventListener('scroll', () => {
        const currentScroll = window.pageYOffset;
        
        if (currentScroll > 50) {
            navbar.style.boxShadow = '0 10px 30px rgba(0, 0, 0, 0.3)';
        } else {
            navbar.style.boxShadow = 'none';
        }
        
        lastScroll = currentScroll;
    });
}

// ============================================
// Parallax Effect (Optional)
// ============================================

window.addEventListener('scroll', () => {
    const floatingElements = document.querySelectorAll('.float-item');
    const scrollY = window.pageYOffset;
    
    floatingElements.forEach((element, index) => {
        const speed = 50 + index * 10;
        element.style.transform = `translateY(${scrollY / speed}px)`;
    });
});

// ============================================
// Download Button Handlers
// ============================================

function downloadFile(filename, version) {
    console.log(`Downloading ${filename} (${version})`);
    // This will be handled by the downloads.html page
}

// ============================================
// Utility Functions
// ============================================

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        alert('Copied to clipboard!');
    });
}

// Add animation delay utility
function staggerChildren(selector, delay = 100) {
    const children = document.querySelectorAll(selector);
    children.forEach((child, index) => {
        child.style.animationDelay = `${index * delay}ms`;
    });
}

// ============================================
// Page Load Animation
// ============================================

window.addEventListener('load', () => {
    document.body.style.opacity = '1';
});
