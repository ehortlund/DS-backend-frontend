document.addEventListener('DOMContentLoaded', () => {
    console.log("live-status.js laddad och DOM är redo");

    // Lista med meddelanden för rullande text
    let liveStatusMessages = [
        { template: "Actively searching for [10-20] energy deals in {region}", numbers: [10, 20] },
        { template: "Scraping government news sites for finance deals in {region}" },
        { template: "Tracking [5-15] healthcare opportunities in {region}", numbers: [5, 15] },
        { template: "Analyzing new military contracts in {region}" },
        { template: "Discovering [15-25] tech deals in {region}", numbers: [15, 25] },
        { template: "Monitoring [8-18] infrastructure projects in {region}", numbers: [8, 18] },
        { template: "Exploring finance deals on [3-10] European news portals", numbers: [3, 10] },
        { template: "Scanning for [12-22] energy contracts in {region}", numbers: [12, 22] },
        { template: "Reviewing [7-17] healthcare deals in {region}", numbers: [7, 17] },
        { template: "Searching global markets for military deals in {region}" }
    ];

    // Lista med regioner för randomisering
    const regions = ["Middle-East", "Europe", "North America", "Asia", "South America", "Africa", "Australia", "Global Markets"];

    // Funktion för att slumpa ett nummer inom ett intervall
    const getRandomNumber = (min, max) => Math.floor(Math.random() * (max - min + 1)) + min;

    // Funktion för att slumpa en region
    const getRandomRegion = () => regions[Math.floor(Math.random() * regions.length)];

    // Funktion för att blanda arrayen (Fisher-Yates shuffle)
    const shuffleArray = (array) => {
        const shuffled = [...array];
        for (let i = shuffled.length - 1; i > 0; i--) {
            const j = Math.floor(Math.random() * (i + 1));
            [shuffled[i], shuffled[j]] = [shuffled[j], shuffled[i]];
        }
        return shuffled;
    };

    // Blanda meddelanden vid start
    liveStatusMessages = shuffleArray(liveStatusMessages);
    console.log("Initial blandad lista:", liveStatusMessages.map(msg => msg.template));

    // Funktion för att slumpa och uppdatera rullande text
    const updateLiveStatus = () => {
        const liveStatusWrapper = document.querySelector('.live-status-wrapper');
        if (!liveStatusWrapper) {
            console.error("Kunde inte hitta live-status-wrapper elementet!");
            return;
        }

        // Ta det första meddelandet i listan
        const message = liveStatusMessages[0];
        let text = message.template;

        // Felsökningslogg
        console.log("Valt meddelande:", text);

        // Ersätt nummer om det finns (alltid randomiserat)
        if (message.numbers) {
            const randomNumber = getRandomNumber(message.numbers[0], message.numbers[1]);
            text = text.replace(/\[\d+-\d+\]/, randomNumber);
            console.log("Slumpat nummer:", randomNumber);
        }

        // Ersätt region om det finns (alltid randomiserat)
        if (text.includes("{region}")) {
            const randomRegion = getRandomRegion();
            text = text.replace("{region}", randomRegion);
            console.log("Slumpad region:", randomRegion);
        }

        // Skapa ett nytt span-element
        const newStatusText = document.createElement('span');
        newStatusText.className = 'live-status';
        newStatusText.id = 'live-status-text';
        newStatusText.textContent = text; // Ingen duplicering

        // Rensa wrapper och lägg till det nya elementet
        liveStatusWrapper.innerHTML = '';
        liveStatusWrapper.appendChild(newStatusText);

        console.log("Uppdaterad text:", newStatusText.textContent);

        // Flytta det använda meddelandet till slutet av listan
        liveStatusMessages.push(liveStatusMessages.shift());
        console.log("Uppdaterad lista:", liveStatusMessages.map(msg => msg.template));
    };

    // Kör funktionen direkt och sedan var 7:e sekund
    updateLiveStatus();
    setInterval(() => {
        console.log("Uppdaterar live-status...");
        updateLiveStatus();
    }, 7000);
});