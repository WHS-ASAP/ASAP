class PackageList extends HTMLElement {
  constructor() {
    super();
    this.attachShadow({ mode: "open" });
  }

  connectedCallback() {
    fetch("/api/sidebar_list")
      .then((response) => response.json())
      .then((packages) => {
        this.shadowRoot.innerHTML = `
          <style>
            .nav-item {
              -webkit-box-flex: 1;
              -ms-flex: 1 1 auto;
              flex: 1 1 auto;
            }
            .nav-item:hover {
              background-color: #000000;
              color: #ffffff;
            }
            .nav-item a {
              margin-left: 10px;
              text-decoration: none;
              color: #ffffff;
              flex-grow: 1;
            }
            .nav {
              --bs-nav-link-padding-x: 1rem;
              --bs-nav-link-padding-y: 0.5rem;
              --bs-nav-link-font-weight: ;
              --bs-nav-link-color: var(--bs-link-color);
              --bs-nav-link-hover-color: #8bb9fe;
              --bs-nav-link-disabled-color: var(--bs-secondary-color);
              display: -webkit-box;
              display: -ms-flexbox;
              display: flex;
              -ms-flex-wrap: wrap;
              flex-wrap: wrap;
              padding-left: 0;
              margin-bottom: 0;
              list-style: none;
            }

            .nav-link {
              display: block;
              padding: var(--bs-nav-link-padding-y) var(--bs-nav-link-padding-x);
              font-size: 13px;
              font-weight: var(--bs-nav-link-font-weight);
              color: #8bb9fe;
              text-decoration: none;
              background: none;
              border: 0;
              -webkit-transition: color 0.15s ease-in-out, background-color 0.15s ease-in-out, border-color 0.15s ease-in-out;
              transition: color 0.15s ease-in-out, background-color 0.15s ease-in-out, border-color 0.15s ease-in-out;
            }
          </style>

          ${packages
            .map(
              (pkg) => `
                <li class="nav-item">
                  <a class="nav-link">${pkg}</a>
                </li>
              `
            )
            .join("")}
        `;

        this.shadowRoot.querySelectorAll(".nav-item").forEach((item) => {
          item.addEventListener("click", () => {
            window.location.href = `/package/${item.textContent.trim()}`;
          });
        });
      });
  }
}

customElements.define("package-list", PackageList);
