<script>
  import { store } from '../lib/store.svelte';
  import { ICONS } from '../lib/constants';
  import './NavBar.css';
  
  let { activeTab, onTabChange } = $props();
  let showLangMenu = $state(false);
  
  // Refs
  let navContainer;
  let langButtonRef;
  let menuRef;
  let tabRefs = {};

  const TABS = [
    { id: 'status', icon: ICONS.home },
    { id: 'config', icon: ICONS.settings },
    { id: 'modules', icon: ICONS.modules },
    { id: 'logs', icon: ICONS.description }
  ];

  // Dynamically load all locale JSON files to extract available languages and display names.
  // "eager: true" loads the content immediately, allowing us to read the "lang.display" field.
  const localeModules = import.meta.glob('../locales/*.json', { eager: true });
  
  const languages = Object.entries(localeModules).map(([path, mod]) => {
    // Extract language code from filename (e.g., "../locales/zhs.json" -> "zhs")
    const match = path.match(/\/([^/]+)\.json$/);
    const code = match ? match[1] : 'en';
    
    // Extract display name from the JSON content (mod.default is the JSON object)
    // Fallback to uppercase code if display name is missing
    const name = mod.default?.lang?.display || code.toUpperCase();
    
    return { code, name };
  }).sort((a, b) => {
    // Optional: Keep English at the top, sort others alphabetically
    if (a.code === 'en') return -1;
    if (b.code === 'en') return 1;
    return a.code.localeCompare(b.code);
  });

  $effect(() => {
    if (activeTab && tabRefs[activeTab] && navContainer) {
      const tab = tabRefs[activeTab];
      const containerWidth = navContainer.clientWidth;
      const tabLeft = tab.offsetLeft;
      const tabWidth = tab.clientWidth;
      const scrollLeft = tabLeft - (containerWidth / 2) + (tabWidth / 2);
      
      navContainer.scrollTo({
        left: scrollLeft,
        behavior: 'smooth'
      });
    }
  });

  function toggleTheme() {
    store.setTheme(store.theme === 'light' ? 'dark' : 'light');
  }

  function setLang(code) {
    store.setLang(code);
    showLangMenu = false;
  }
  
  // Close menu when clicking outside
  function handleOutsideClick(e) {
    if (showLangMenu && 
        menuRef && !menuRef.contains(e.target) && 
        langButtonRef && !langButtonRef.contains(e.target)) {
      showLangMenu = false;
    }
  }
</script>

<svelte:window onclick={handleOutsideClick} />

<header class="app-bar">
  <div class="app-bar-content">
    <h1 class="screen-title">{store.L.common.appName}</h1>
    <div class="top-actions">
      <button class="btn-icon" onclick={toggleTheme} title={store.L.common.theme}>
        <svg viewBox="0 0 24 24"><path d={store.theme === 'light' ? ICONS.dark_mode : ICONS.light_mode} fill="currentColor"/></svg>
      </button>
      <button 
        class="btn-icon" 
        bind:this={langButtonRef}
        onclick={() => showLangMenu = !showLangMenu} 
        title={store.L.common.language}
      >
        <svg viewBox="0 0 24 24"><path d={ICONS.translate} fill="currentColor"/></svg>
      </button>
    </div>
  </div>
  
  {#if showLangMenu}
    <div class="menu-dropdown" bind:this={menuRef}>
      {#each languages as l}
        <button class="menu-item" onclick={() => setLang(l.code)}>{l.name}</button>
      {/each}
    </div>
  {/if}

  <nav class="nav-tabs" bind:this={navContainer}>
    {#each TABS as tab}
      <button 
        class="nav-tab {activeTab === tab.id ? 'active' : ''}" 
        onclick={() => onTabChange(tab.id)}
        bind:this={tabRefs[tab.id]}
      >
        <svg viewBox="0 0 24 24"><path d={tab.icon}/></svg>
        {store.L.tabs[tab.id]}
      </button>
    {/each}
  </nav>
</header>