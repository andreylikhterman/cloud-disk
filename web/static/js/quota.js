async function loadQuota() {
  try {
    const res = await fetch(`${API_BASE}/quota`, {
      headers: { Authorization: `Bearer ${authToken}` },
    });

    if (res.status === 401) {
      logout();
      return;
    }

    if (res.ok) {
      const data = await res.json();
      if (data.success) {
        updateQuotaDisplay(data.data);
      }
    }
  } catch (e) {
    console.error("Failed to load quota:", e);
  }
}

function updateQuotaDisplay(quota) {
  const display = document.getElementById("quotaDisplay");
  const quotaText = document.getElementById("quotaText");
  const quotaBar = document.getElementById("quotaBar");
  const quotaDetails = document.getElementById("quotaDetails");

  if (!quota || !quota.storage) {
    display.style.display = "none";
    return;
  }

  display.style.display = "block";

  const percent = quota.storage.usedPercent || 0;
  quotaText.textContent = `${quota.storage.usedFormatted} / ${quota.storage.quotaFormatted} (${percent.toFixed(1)}%)`;
  quotaBar.style.width = `${Math.min(percent, 100)}%`;

  if (percent >= 95) {
    quotaBar.style.background = "linear-gradient(90deg, #f44336, #d32f2f)";
  } else if (percent >= 80) {
    quotaBar.style.background = "linear-gradient(90deg, #ff9800, #f57c00)";
  } else {
    quotaBar.style.background = "linear-gradient(90deg, #4CAF50, #45a049)";
  }

  quotaDetails.textContent = "";
}
