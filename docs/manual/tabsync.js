document.addEventListener("DOMContentLoaded", function () {
  const tabSync = () => {
    const tabs = document.querySelectorAll(".tabbed-set > input, .tabbed-alternate input");

    for (const tab of tabs) {
      tab.addEventListener("click", () => {
        if (tab.dataset.syncing === "true") return;
        
        const currentLabel = document.querySelector(`label[for="${tab.id}"]`);
        if (!currentLabel) return;

        const pos = currentLabel.getBoundingClientRect().top;
        const labelText = currentLabel.textContent.trim();

        const allLabels = document.querySelectorAll(
          ".tabbed-set > label, .tabbed-alternate > .tabbed-labels > label"
        );

        for (const label of allLabels) {
          if (label.textContent.trim() === labelText) {
            const inputId = label.getAttribute("for");
            const input = document.getElementById(inputId);
            if (input && input !== tab) {
              input.dataset.syncing = "true";
              input.click();
              input.dataset.syncing = "false";
            }
          }
        }

        const delta = currentLabel.getBoundingClientRect().top - pos;
        window.scrollBy(0, delta);
      });
    }
  };

  tabSync();
});