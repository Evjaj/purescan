document.addEventListener('DOMContentLoaded', function () {
    const accordion = document.getElementById('purescan-help-accordion');
    if (!accordion) return;

    const sections = accordion.querySelectorAll('.purescan-help-section');

    sections.forEach(section => {
        const title = section.querySelector('.purescan-help-title');
        if (!title) return;

        const toggleSection = () => {
            const isActive = section.classList.contains('active');
            section.classList.toggle('active');
            
            // Update aria-expanded immediately
            title.setAttribute('aria-expanded', !isActive);
        };

        title.addEventListener('click', (e) => {
            e.preventDefault();
            toggleSection();
        });

        title.addEventListener('keydown', (e) => {
            if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                toggleSection();
            }
        });

        // Accessibility
        title.setAttribute('tabindex', '0');
        title.setAttribute('role', 'button');
        title.setAttribute('aria-expanded', section.classList.contains('active'));
    });
});