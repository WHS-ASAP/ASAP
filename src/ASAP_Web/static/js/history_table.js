// static/js/history_table.js

document.addEventListener("DOMContentLoaded", function () {
  fetch("/api/history_table")
    .then((response) => response.json())
    .then((data) => {
      const tbody = document.querySelector("table tbody");
      tbody.innerHTML = ""; // Clear existing rows
      data.forEach((item) => {
        const tr = document.createElement("tr");
        tr.innerHTML = `
          <td>${item.package_name}</td>
          <td>${item.platform}</td>
          <td>${item.type}</td>
          <td>${item.created_at}</td>
          <td>
            <div class="badge badge-${
              item.risk === "High" ? "danger" : item.risk === "Medium" ? "caution" : "warning"
            } p-2">${item.risk}</div>
          </td>
        `;
        tr.addEventListener("click", () => {
          window.location.href = `/package/${item.package_name}`;
        });
        tbody.appendChild(tr);
      });
    });
});
