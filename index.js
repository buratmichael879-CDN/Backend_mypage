(function(){
    const mp = [
        {name:"<span>My</span>Page"}
    ];

    const navItems = [
        {label: "Home", href: "#home"},
        {label: "About", href: "#about"},
        {label: "Contact", href: "#contact"}
    ];

    const root = document.getElementById('root');

    // Build nav HTML
    const navHTML = navItems.map(item => `<li><a href="${item.href}">${item.label}</a></li>`).join('');

    // Set full innerHTML
    root.innerHTML = `
        <div class="top">
            <h1>${mp[0].name}</h1>
            <nav class="nav">
                ${navHTML}
            </nav>
        </div>
    `;
})();
