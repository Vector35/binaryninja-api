/**
 * Binary Ninja Dark Mode - System Preference with Cookie Persistence
 * Follows system color scheme automatically via CSS
 * Provides console toggle for testing with cookie-based persistence
 */

(function() {
    'use strict';

    const COOKIE_NAME = 'bn-docs-theme';
    const COOKIE_DAYS = 365;

    /**
     * Get cookie value by name
     */
    function getCookie(name) {
        const value = `; ${document.cookie}`;
        const parts = value.split(`; ${name}=`);
        if (parts.length === 2) return parts.pop().split(';').shift();
        return null;
    }

    /**
     * Set cookie value
     */
    function setCookie(name, value, days) {
        const date = new Date();
        date.setTime(date.getTime() + (days * 24 * 60 * 60 * 1000));
        const expires = `expires=${date.toUTCString()}`;
        document.cookie = `${name}=${value};${expires};path=/`;
    }

    /**
     * Delete cookie
     */
    function deleteCookie(name) {
        document.cookie = `${name}=;expires=Thu, 01 Jan 1970 00:00:00 UTC;path=/`;
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
     * Console-accessible toggle function with cookie persistence
     * Usage: bnToggleDarkMode('dark'), bnToggleDarkMode('light'), or bnToggleDarkMode('auto')
     */
    window.bnToggleDarkMode = function(mode) {
        if (mode === 'dark') {
            applyTheme('dark');
            setCookie(COOKIE_NAME, 'dark', COOKIE_DAYS);
            console.log('Dark mode: FORCED ON (saved to cookie, will persist across reloads)');
        } else if (mode === 'light') {
            applyTheme('light');
            setCookie(COOKIE_NAME, 'light', COOKIE_DAYS);
            console.log('Dark mode: FORCED OFF (saved to cookie, will persist across reloads)');
        } else if (mode === 'auto') {
            applyTheme('auto');
            deleteCookie(COOKIE_NAME);
            console.log('Dark mode: AUTO (following system preference, cookie cleared)');
        } else {
            console.log('Usage: bnToggleDarkMode("dark"), bnToggleDarkMode("light"), or bnToggleDarkMode("auto")');
            console.log('Current setting:', getCookie(COOKIE_NAME) || 'auto (system preference)');
        }
    };

    /**
     * Initialize theme on page load
     */
    function init() {
        const savedTheme = getCookie(COOKIE_NAME);

        if (savedTheme) {
            applyTheme(savedTheme);
            console.log(`Binary Ninja Docs: Theme loaded from cookie: ${savedTheme}`);
        } else {
            console.log('Binary Ninja Docs: Following system preference (no cookie set)');
        }

        console.log('Use bnToggleDarkMode("dark"), bnToggleDarkMode("light"), or bnToggleDarkMode("auto") to change theme');
    }

    // Initialize on page load
    init();
})();
