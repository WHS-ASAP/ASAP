class Sidebar extends HTMLElement {
  constructor() {
    super(); // 항상 최상위 생성자 호출 필수
    this.attachShadow({ mode: "open" }); // Shadow DOM
  }

  connectedCallback() {
    const packages = JSON.parse(this.getAttribute("packages"));

    this.shadowRoot.innerHTML = `
      <style>
        .sidebar-container {
          padding: 20px;
          background-color: #FFFFFF;
          border-right: 1px solid #E0E0E0;
          height: 100%;
        }
        .sidebar-container h2 {
          text-align: center;
          margin-bottom: 20px;
          color: #4CAF50;
        }
        .package-list {
          list-style: none;
          padding: 0;
        }
        .package-list li {
          display: flex;
          align-items: center;
          padding: 10px;
          border: 1px solid #4CAF50;
          margin-bottom: 10px;
          border-radius: 5px;
          transition: background-color 0.3s;
          cursor: pointer;
        }
        .package-list li:hover {
          background-color: #f0f0f0;
        }
        .package-list li a {
          margin-left: 10px;
          text-decoration: none;
          color: #333;
          flex-grow: 1;
        }
        .package-list li .number {
          background-color: #4CAF50;
          color: white;
          border-radius: 50%;
          width: 24px;
          height: 24px;
          display: flex;
          align-items: center;
          justify-content: center;
          font-size: 14px;
        }
      </style>
      <div class="sidebar-container">
        <h2>Analyzed Packages</h2>
        <ul class="package-list">
          ${packages
            .map(
              (pkg, index) => `
            <li data-link="${pkg.link}">
              <div class="number">${index + 1}</div>
              <a href="${pkg.link}">${pkg.name}</a>
            </li>
          `
            )
            .join("")}
        </ul>
      </div>
    `;

    this.shadowRoot.querySelectorAll(".package-list li").forEach((item) => {
      item.addEventListener("click", () => {
        window.location.href = item.getAttribute("data-link");
      });
    });
  }
}

customElements.define("side-bar", Sidebar);
