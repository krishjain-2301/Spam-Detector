// Toggle Functionality
document.addEventListener('DOMContentLoaded', () => {
    // Get toggle and status elements
    const monitoringToggle = document.getElementById('toggle-monitoring');
    const bgProtectionToggle = document.getElementById('toggle-bg-protection');
    const monitoringStatus = document.getElementById('monitoring-status-text');
    const bgStatus = document.getElementById('bg-status-text');

    // Function to update status display
    function updateStatus(statusElement, isActive) {
        if (statusElement) {
            // When toggle is right (checked) = Active, left (unchecked) = Inactive
            statusElement.textContent = isActive ? 'Active' : 'Inactive';
            statusElement.style.color = isActive ? '#22c55e' : '#991b1b';
            statusElement.style.fontWeight = 'bold';
        }
    }

    // Monitoring Toggle Handler
    monitoringToggle.addEventListener('change', async () => {
        // Toggle is right (checked) = start monitoring, left (unchecked) = stop monitoring
        const isActive = monitoringToggle.checked;
        console.log('[Toggle] Monitoring:', isActive ? 'Starting' : 'Stopping');
        updateStatus(monitoringStatus, isActive);
        await window.electronAPI.toggleMonitoring();
    });

    // Background Protection Toggle Handler
    bgProtectionToggle.addEventListener('change', async () => {
        // Toggle is right (checked) = protection on, left (unchecked) = protection off
        const isActive = bgProtectionToggle.checked;
        console.log('[Toggle] Background Protection:', isActive ? 'Starting' : 'Stopping');
        updateStatus(bgStatus, isActive);
        await window.electronAPI.toggleBackgroundProtection();
    });

    // Get initial states from backend
    async function initializeStates() {
        if (window.electronAPI) {
            try {
                // Get monitoring state
                const monitoringActive = await window.electronAPI.getMonitoringStatus();
                monitoringToggle.checked = monitoringActive;
                updateStatus(monitoringStatus, monitoringActive);

                // Get background protection state
                const bgActive = await window.electronAPI.getBackgroundProtection();
                bgProtectionToggle.checked = bgActive;
                updateStatus(bgStatus, bgActive);
            } catch (error) {
                console.error('Error initializing toggle states:', error);
            }
        }
    }

    // Initialize toggle states
    initializeStates();
});