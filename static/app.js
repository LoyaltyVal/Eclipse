document.addEventListener("submit", (event) => {
  const message = event.target.dataset.confirm;
  if (message && !window.confirm(message)) {
    event.preventDefault();
  }
});

document.querySelectorAll(".save-form").forEach((form) => {
  const boardSelect = form.querySelector('select[name="board_id"]');
  const button = form.querySelector("[data-save-toggle]");
  if (!boardSelect || !button) return;

  const updateLabel = () => {
    const isSaved = boardSelect.selectedOptions[0]?.dataset.saved === "true";
    button.textContent = isSaved ? "Unsave pin" : "Save pin";
  };

  boardSelect.addEventListener("change", updateLabel);
  updateLabel();
});
