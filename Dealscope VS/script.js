const dealScope = {
    init: async function () {
        console.log("DealScope JavaScript is running!");
        this.handleMobileNav();
        this.handleFadeInAnimations('.fade-in');

        // Hämtar och renderar deals
        console.log("Hämtar deals.json...");
        try {
            const response = await fetch('deals.json');
            const deals = await response.json();
            console.log("Data:", deals);

            // Spara deals för filtrering och sortering
            this.allDeals = deals;
            this.currentDeals = [...deals];
            this.generateDealCards(this.currentDeals, ".deals-container");
            console.log("generateDealCards anropad");

            // Sätt upp dropdowns och händelser
            this.setupControls();
        } catch (error) {
            console.error("Fel vid hämtning av deals:", error);
        }

        // Back-button-händelse
        const dealDetailsContainer = document.querySelector(".deal-details-container");
        if (dealDetailsContainer) {
            dealDetailsContainer.addEventListener("click", (event) => {
                if (event.target.classList.contains("back-button")) {
                    this.handleGoBack();
                }
            });
        }

        // Händelselyssnare för "View Deal"-knappar på dokumentnivå
        document.addEventListener("click", (event) => {
            if (event.target.classList.contains("deal-recommendation-button")) {
                const dealTitle = event.target.getAttribute("data-title");
                console.log(`Klickade på View Deal för: ${dealTitle}`); // Felsökningslogg
                this.showDealDetails(dealTitle);
            }
        });

        // Hantera bakåtnavigering med webbläsarens bakåtknapp
        window.onpopstate = (event) => {
            console.log("Bakåtnavigering detekterad", event.state); // Felsökningslogg
            const dealDetailsContainer = document.querySelector(".deal-details-container");
            if (dealDetailsContainer.style.display === "block") {
                // Om detaljvyn är öppen, simulera "Go back"-knappens beteende
                this.handleGoBack();
            }
        };

        // Sätt initialt tillstånd för deals-vyn
        history.replaceState({ page: 'deals' }, '', window.location.href);
    },

    handleGoBack: function () {
        const dealDetailsHeader = document.querySelector(".deal-details-header");
        const dealDetailsContainer = document.querySelector(".deal-details-container");
        const dealRecommendations = document.querySelector(".deal-recommendations");
        const dealsContainer = document.querySelector(".deals-container");
        const dealSectionTitle = document.querySelector(".deal-section-title");
        const dealControls = document.querySelector(".deal-controls");

        if (dealDetailsHeader) dealDetailsHeader.style.display = "none";
        dealDetailsContainer.style.display = "none";
        if (dealRecommendations) dealRecommendations.style.display = "none";
        if (dealsContainer) dealsContainer.style.display = "block";
        if (dealSectionTitle) dealSectionTitle.style.display = "block";
        if (dealControls) dealControls.style.display = "flex"; // Visa deal-controls igen

        // Återställ tillståndet till deals-vyn
        history.replaceState({ page: 'deals' }, '', window.location.href);
    },

    setupControls: function () {
        const searchInput = document.querySelector('#deal-search');
        const searchSuggestions = document.querySelector('#deal-suggestions');
        const categoryInput = document.querySelector('#deal-category');
        const categorySuggestions = document.querySelector('#category-suggestions');
        const sortInput = document.querySelector('#deal-sort');
        const sortSuggestions = document.querySelector('#sort-suggestions');

        // Sätt initialt tillstånd för dropdowns (stängda)
        searchSuggestions.style.display = 'none';
        categorySuggestions.style.display = 'none';
        sortSuggestions.style.display = 'none';

        // Kategorier och sorteringsalternativ
        const categories = ['Military', 'Healthcare', 'Finance', 'Energy', 'All'];
        const sortOptions = ['Date ↑', 'Date ↓', 'Deal size ↑', 'Deal size ↓'];

        // Fyll kategoridropdown
        categories.forEach(category => {
            const option = document.createElement('div');
            option.className = 'suggestion-item';
            option.textContent = category;
            option.addEventListener('click', (event) => {
                console.log(`Vald kategori: ${category}`); // Felsökningslogg
                categoryInput.value = category;
                categorySuggestions.style.display = 'none';
                categoryInput.classList.remove('active');
                this.filterDeals(searchInput.value, category === 'All' ? '' : category.toLowerCase());
            });
            categorySuggestions.appendChild(option);
        });

        // Fyll sorteringsdropdown
        sortOptions.forEach(sortOption => {
            const option = document.createElement('div');
            option.className = 'suggestion-item';
            option.textContent = sortOption;
            option.addEventListener('click', (event) => {
                sortInput.value = sortOption;
                sortSuggestions.style.display = "none";
                sortInput.classList.remove('active');
                this.sortDeals(sortOption);
            });
            sortSuggestions.appendChild(option);
        });

        // Sökfält: Visa/dölj dropdown vid fokus och input
        searchInput.addEventListener('focus', () => {
            console.log("Sökfält fokuserat"); // Felsökningslogg
            this.updateSearchSuggestions(searchInput.value);
        });

        searchInput.addEventListener('input', () => {
            console.log(`Sökterm: ${searchInput.value}`); // Felsökningslogg
            this.updateSearchSuggestions(searchInput.value);
            this.filterDeals(searchInput.value, categoryInput.value.toLowerCase() === 'all' ? '' : categoryInput.value.toLowerCase());
        });

        searchInput.addEventListener('blur', () => {
            setTimeout(() => {
                searchSuggestions.style.display = 'none';
            }, 150);
        });

        // Kategori: Visa/dölj dropdown vid klick
        categoryInput.addEventListener('click', (event) => {
            console.log("Klickade på category-fältet"); // Felsökningslogg
            const isVisible = categorySuggestions.style.display === 'block';
            categorySuggestions.style.display = isVisible ? 'none' : 'block';
            categoryInput.classList.toggle('active', !isVisible);
            if (isVisible) {
                categoryInput.blur(); // Ta bort fokus för att förhindra autofyll
            }
        });

        categoryInput.addEventListener('blur', () => {
            setTimeout(() => {
                categorySuggestions.style.display = 'none';
                categoryInput.classList.remove('active');
            }, 150);
        });

        // Sort by: Visa/dölj dropdown vid klick
        sortInput.addEventListener('click', (event) => {
            console.log("Klickade på sort by-fältet"); // Felsökningslogg
            const isVisible = sortSuggestions.style.display === 'block';
            sortSuggestions.style.display = isVisible ? 'none' : 'block';
            sortInput.classList.toggle('active', !isVisible);
            if (isVisible) {
                sortInput.blur(); // Ta bort fokus för att förhindra autofyll
            }
        });

        sortInput.addEventListener('blur', () => {
            setTimeout(() => {
                sortSuggestions.style.display = 'none';
                sortInput.classList.remove('active');
            }, 150);
        });

        // Stäng dropdowns vid klick utanför
        document.addEventListener('click', (event) => {
            if (!searchInput.parentElement.contains(event.target)) {
                searchSuggestions.style.display = 'none';
            }
            if (!categoryInput.parentElement.contains(event.target)) {
                categorySuggestions.style.display = 'none';
                categoryInput.classList.remove('active');
            }
            if (!sortInput.parentElement.contains(event.target)) {
                sortSuggestions.style.display = 'none';
                sortInput.classList.remove('active');
            }
        });
    },

    updateSearchSuggestions: function (searchTerm) {
        const searchSuggestions = document.querySelector('#deal-suggestions');
        searchSuggestions.innerHTML = '';

        if (searchTerm.trim() === '') {
            searchSuggestions.style.display = 'none';
            return;
        }

        const suggestions = new Set();
        this.allDeals.forEach(deal => {
            if (deal.title.toLowerCase().includes(searchTerm.toLowerCase())) {
                suggestions.add(deal.title);
            }
            if (deal.description.toLowerCase().includes(searchTerm.toLowerCase())) {
                suggestions.add(deal.title);
            }
        });

        suggestions.forEach(suggestion => {
            const option = document.createElement('div');
            option.className = 'suggestion-item';
            option.textContent = suggestion;
            option.addEventListener('click', (event) => {
                document.querySelector('#deal-search').value = suggestion;
                searchSuggestions.style.display = 'none';
                this.filterDeals(suggestion, document.querySelector('#deal-category').value.toLowerCase() === 'all' ? '' : document.querySelector('#deal-category').value.toLowerCase());
            });
            searchSuggestions.appendChild(option);
        });

        if (suggestions.size > 0) {
            searchSuggestions.style.display = 'block';
        } else {
            searchSuggestions.style.display = 'none';
        }
    },

    filterDeals: function (searchTerm, category) {
        console.log(`Filtrerar deals med searchTerm: ${searchTerm}, category: ${category}`); // Felsökningslogg
        this.currentDeals = this.allDeals.filter(deal => {
            const matchesSearch = searchTerm === '' || 
                deal.title.toLowerCase().includes(searchTerm.toLowerCase()) || 
                deal.description.toLowerCase().includes(searchTerm.toLowerCase());
            const matchesCategory = category === '' || 
                (deal.category && deal.category.toLowerCase() === category);
            return matchesSearch && matchesCategory;
        });
        this.generateDealCards(this.currentDeals, ".deals-container");
        const sortOption = document.querySelector('#deal-sort').value;
        if (sortOption) {
            this.sortDeals(sortOption);
        }
    },

    sortDeals: function (sortOption) {
        let sortedDeals = [...this.currentDeals];
        switch (sortOption) {
            case 'Date ↑':
                sortedDeals.sort((a, b) => new Date(a.date) - new Date(b.date));
                break;
            case 'Date ↓':
                sortedDeals.sort((a, b) => new Date(b.date) - new Date(a.date));
                break;
            case 'Deal size ↑':
                sortedDeals.sort((a, b) => {
                    const valueA = parseFloat(a.dealValue ? a.dealValue.replace(/[^0-9.-]+/g, '') : -Infinity);
                    const valueB = parseFloat(b.dealValue ? b.dealValue.replace(/[^0-9.-]+/g, '') : -Infinity);
                    return valueA - valueB;
                });
                break;
            case 'Deal size ↓':
                sortedDeals.sort((a, b) => {
                    const valueA = parseFloat(a.dealValue ? a.dealValue.replace(/[^0-9.-]+/g, '') : Infinity);
                    const valueB = parseFloat(b.dealValue ? b.dealValue.replace(/[^0-9.-]+/g, '') : Infinity);
                    return valueB - valueA;
                });
                break;
            default:
                break;
        }
        this.currentDeals = sortedDeals;
        this.generateDealCards(this.currentDeals, ".deals-container");
    },

    createDealCard: function (deal) {
        var cardTemplate =
            '<article class="deal-example-card" data-state="closed">' +
            '<h2 class="deal-section-heading">' +
            deal.title +
            '</h2>' +
            '<p class="deal-description">' +
            deal.description +
            '</p>' +
            '<ul class="deal-details">' +
            '<li>Category: ' + deal.category + '</li>' +
            '<li>Date: ' + deal.date + '</li>' +
            (deal.dealValue ? '<li>Deal Value: ' + deal.dealValue + '</li>' : '') +
            '</ul>' +
            '<button class="deal-link-button" data-link="' + deal.link + '">Read More</button>' +
            '</article>';
        return cardTemplate;
    },

    generateDealCards: function (deals, containerSelector) {
        const dealsContainer = document.querySelector(containerSelector);
        if (dealsContainer) {
            dealsContainer.innerHTML = '';
            if (deals.length === 0) {
                dealsContainer.innerHTML = '<p class="no-deals-message">No deals found matching your search :(</p>';
                return;
            }
            deals.forEach(deal => {
                const cardHTML = this.createDealCard(deal);
                dealsContainer.innerHTML += cardHTML;
            });
            this.addDealCardEventListeners(dealsContainer);
        }
    },

    addDealCardEventListeners: function (dealsContainer) {
        // Ta bort tidigare lyssnare för att undvika dubletter
        dealsContainer.removeEventListener("click", this.handleCardClick);
        this.handleCardClick = (event) => {
            const card = event.target.closest(".deal-example-card");
            const readMoreButton = event.target.classList.contains("deal-link-button");

            console.log("Klick på kort registrerat"); // Felsökningslogg

            // Hantera klick på "Read More"-knappen
            if (readMoreButton) {
                event.preventDefault();
                const dealTitle = card.querySelector(".deal-section-heading").textContent;
                this.showDealDetails(dealTitle);
                return;
            }

            // Hantera klick på kortet för att toggla open/closed
            if (card && !event.target.closest('#category-suggestions')) {
                const state = card.getAttribute("data-state");
                console.log(`Togglar kortstate: ${state} -> ${state === "closed" ? "open" : "closed"}`); // Felsökningslogg
                card.setAttribute("data-state", state === "closed" ? "open" : "closed");
            }
        };
        dealsContainer.addEventListener("click", this.handleCardClick);
    },

    showDealDetails: function (dealTitle) {
        fetch("deals.json")
            .then(response => response.json())
            .then(data => {
                const deal = data.find(d => d.title === dealTitle);
                if (deal) {
                    const dealDetailsHeader = document.querySelector(".deal-details-header");
                    const dealDetailsContainer = document.querySelector(".deal-details-container");
                    const dealRecommendations = document.querySelector(".deal-recommendations") || document.createElement("div");
                    const dealsContainer = document.querySelector(".deals-container");
                    const dealSectionTitle = document.querySelector(".deal-section-title");
                    const dealControls = document.querySelector(".deal-controls");

                    dealDetailsHeader.innerHTML = `<h2>${deal.title}</h2><p>${deal.description}</p>`;
                    dealDetailsContainer.innerHTML = this.generateDealDetails(deal);
                    dealRecommendations.className = "deal-recommendations";
                    dealRecommendations.innerHTML = this.generateDealRecommendations(data, dealTitle);
                    
                    // Placera deal-recommendations efter deal-details-container
                    if (!dealRecommendations.parentNode) {
                        dealDetailsContainer.parentNode.insertBefore(dealRecommendations, dealDetailsContainer.nextSibling);
                    }

                    dealDetailsHeader.style.display = "block";
                    dealDetailsContainer.style.display = "block";
                    dealRecommendations.style.display = "block";
                    dealsContainer.style.display = "none";
                    if (dealSectionTitle) dealSectionTitle.style.display = "none";
                    if (dealControls) dealControls.style.display = "none"; // Dölj deal-controls

                    // Lägg till tillstånd för detaljvyn i historiken
                    history.pushState({ page: 'details' }, '', window.location.href);

                    // Scrolla till toppen av sidan
                    window.scrollTo({ top: 0, behavior: 'smooth' });
                }
            });
    },

    generateDealDetails: function (deal) {
        return `
            <div class="deal-details-content">
                <h3>Deal Overview</h3>
                <ul class="deal-overview-list">
                    <li>Deal Value: <span>${deal.dealValue || 'N/A'}</span></li>
                    <li>Industry: <span>${deal.industry || 'N/A'}</span></li>
                    <li>Date: <span>${deal.date}</span></li>
                    <li>Impact: <span>${deal.impact || 'N/A'}</span></li>
                </ul>

                <h3>Major Contractors and Partners</h3>
                <ul class="major-contractors-list">
                    <li>Buyer: <span>${deal.buyer || 'N/A'}</span></li>
                    <li>Seller: <span>${deal.seller || 'N/A'}</span></li>
                </ul>

                <h3>Potential Subcontractors and Partners</h3>
                <ul class="potential-subcontractors-list">
                    ${deal.subcontractors.map(subcontractor => `<li>${subcontractor}</li>`).join("")}
                </ul>

                <button class="back-button">Go back</button>
            </div>
        `;
    },

    generateDealRecommendations: function (deals, currentDealTitle) {
        // Filtrera bort den aktuella dealen och ta de första tre andra deals
        const otherDeals = deals.filter(deal => deal.title !== currentDealTitle).slice(0, 3);
        return `
            <h3 class="deal-recommendations-title">More deals</h3>
            ${otherDeals.map(deal => `
                <div class="deal-recommendation">
                    <span class="deal-recommendation-title">${deal.title}</span>
                    <span class="deal-recommendation-value">Value: ${deal.dealValue || 'N/A'}</span>
                    <button class="deal-recommendation-button" data-title="${deal.title}">View Deal</button>
                </div>
            `).join('')}
        `;
    },

    handleMobileNav: function () {
        const menuBtn = document.querySelector('.menu-btn');
        const mobileNav = document.querySelector('.mobile-nav');

        if (menuBtn && mobileNav) {
            menuBtn.addEventListener('click', () => {
                menuBtn.classList.toggle('active');
                mobileNav.classList.toggle('visible');
            });
        } else {
            console.error("Kunde inte hitta menyknappen eller mobilnavigeringen.");
        }
    },

    handleFadeInAnimations: function (selector) {
        document.addEventListener("DOMContentLoaded", () => {
            const fadeIns = document.querySelectorAll(selector);
            const observer = new IntersectionObserver((entries, observer) => {
                entries.forEach(entry => {
                    if (entry.isIntersecting) {
                        entry.target.classList.add('show');
                        observer.unobserve(entry.target);
                    }
                });
            });
            fadeIns.forEach(fadeIn => {
                observer.observe(fadeIn);
            });
        });
    },

};

dealScope.init();