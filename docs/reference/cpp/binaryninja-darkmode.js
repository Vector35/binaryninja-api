/**
 * Binary Ninja Dark Mode - System Preference with localStorage Persistence
 * Follows system color scheme automatically via CSS
 * Provides console toggle for testing with localStorage-based persistence
 */

(function() {
    'use strict';

    const STORAGE_KEY = 'bn-docs-theme';
    const STORAGE_TIMESTAMP_KEY = 'bn-docs-theme-timestamp';
    const EXPIRY_HOURS = 24;

    /**
     * Get theme from localStorage if not expired
     */
    function getTheme() {
        try {
            const theme = localStorage.getItem(STORAGE_KEY);
            const timestamp = localStorage.getItem(STORAGE_TIMESTAMP_KEY);

            if (!theme || !timestamp) {
                return null;
            }

            // Check if expired (24 hours)
            const now = Date.now();
            const age = now - parseInt(timestamp, 10);
            const maxAge = EXPIRY_HOURS * 60 * 60 * 1000; // 24 hours in ms

            if (age > maxAge) {
                // Expired, remove and return null
                removeTheme();
                return null;
            }

            return theme;
        } catch (e) {
            return null;
        }
    }

    /**
     * Set theme in localStorage with timestamp
     */
    function setTheme(value) {
        try {
            localStorage.setItem(STORAGE_KEY, value);
            localStorage.setItem(STORAGE_TIMESTAMP_KEY, Date.now().toString());
        } catch (e) {
            // Silently fail if localStorage is unavailable
        }
    }

    /**
     * Remove theme from localStorage
     */
    function removeTheme() {
        try {
            localStorage.removeItem(STORAGE_KEY);
            localStorage.removeItem(STORAGE_TIMESTAMP_KEY);
        } catch (e) {
            // Silently fail if localStorage is unavailable
        }
    }

    /**
     * Apply theme mode
     */
    function applyTheme(mode) {
        const html = document.documentElement;

        if (mode === 'dark') {
            html.classList.remove('light-mode');
            html.classList.add('dark-mode');
        } else if (mode === 'light') {
            html.classList.remove('dark-mode');
            html.classList.add('light-mode');
        } else {
            // Auto mode - remove both classes to follow system preference
            html.classList.remove('dark-mode');
            html.classList.remove('light-mode');
        }
    }

    /**
     * Console-accessible toggle function with localStorage persistence
     * Usage: bnToggleDarkMode('dark'), bnToggleDarkMode('light'), or bnToggleDarkMode('auto')
     */
    window.bnToggleDarkMode = function(mode) {
        if (mode === 'dark') {
            applyTheme('dark');
            setTheme('dark');
        } else if (mode === 'light') {
            applyTheme('light');
            setTheme('light');
        } else if (mode === 'auto') {
            applyTheme('auto');
            removeTheme();
        }
    };

    /**
     * Update button icon based on current theme
     */
    function updateButtonIcon() {
        const button = document.getElementById('bn-darkmode-toggle');
        if (!button) return;

        const savedTheme = getTheme();

        if (savedTheme === 'light') {
            button.textContent = '☀';
            button.title = 'Light mode (click for Dark)';
        } else if (savedTheme === 'dark') {
            button.textContent = '☾';
            button.title = 'Dark mode (click for Light)';
        } else {
            // No saved theme - show system preference
            const isDarkMode = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches;
            if (isDarkMode) {
                button.textContent = '☾';
                button.title = 'System: Dark (click for Light)';
            } else {
                button.textContent = '☀';
                button.title = 'System: Light (click for Dark)';
            }
        }
    }

    /**
     * Cycle between light and dark mode
     */
    window.cycleDarkMode = function() {
        const savedTheme = getTheme();

        if (savedTheme === 'light') {
            window.bnToggleDarkMode('dark');
        } else {
            // From dark or system -> go to light
            window.bnToggleDarkMode('light');
        }

        updateButtonIcon();
    };

    /**
     * Initialize theme on page load
     */
    function init() {
        const savedTheme = getTheme();

        if (savedTheme) {
            applyTheme(savedTheme);
        }

        // Update button icon after a short delay to ensure DOM is ready
        setTimeout(updateButtonIcon, 100);
    }

    // Initialize on page load
    init();
})();

/**
 * Sidebar Collapse Functionality
 */
(function() {
    'use strict';

    const COOKIE_NAME = 'bn-docs-sidebar-collapsed';
    const COOKIE_DAYS = 365;

    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    function setCookie(name, value, days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        const expires = `expires=${date.toUTCString()}`;
        document.cookie = `${name}=${value};${expires};path=/`;
    }

    function toggleSidebar() {
        const sideNav = document.getElementById('side-nav');
        const docContent = document.getElementById('doc-content');
        const container = document.getElementById('container');
        const button = document.getElementById('sidebar-toggle');
        const top = document.getElementById('top');
        const titlearea = document.getElementById('titlearea');

        if (!sideNav) return;

        const isCollapsed = sideNav.classList.toggle('collapsed');
        if (docContent) docContent.classList.toggle('sidebar-collapsed', isCollapsed);
        if (container) container.classList.toggle('sidebar-collapsed', isCollapsed);
        if (top) top.classList.toggle('collapsed', isCollapsed);
        if (titlearea) titlearea.classList.toggle('collapsed', isCollapsed);
        if (button) button.textContent = isCollapsed ? '→' : '←';

        setCookie(COOKIE_NAME, isCollapsed ? '1' : '0', COOKIE_DAYS);
    }

    function init() {
        // Wait for DOM to be ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', init);
            return;
        }

        const sideNav = document.getElementById('side-nav');
        if (!sideNav) return;

        // Create collapse button
        const button = document.createElement('button');
        button.id = 'sidebar-toggle';
        button.className = 'sidebar-toggle';
        button.textContent = '←';
        button.title = 'Toggle sidebar';
        button.addEventListener('click', toggleSidebar);

        // Insert button at the beginning of side-nav
        sideNav.insertBefore(button, sideNav.firstChild);

        // Restore collapsed state from cookie
        const isCollapsed = getCookie(COOKIE_NAME) === '1';
        if (isCollapsed) {
            sideNav.classList.add('collapsed');
            const docContent = document.getElementById('doc-content');
            const container = document.getElementById('container');
            const top = document.getElementById('top');
            const titlearea = document.getElementById('titlearea');
            if (docContent) docContent.classList.add('sidebar-collapsed');
            if (container) container.classList.add('sidebar-collapsed');
            if (top) top.classList.add('collapsed');
            if (titlearea) titlearea.classList.add('collapsed');
            button.textContent = '→';
        }
    }

    window.bnToggleSidebar = toggleSidebar;
    init();
})();
