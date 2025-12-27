<script lang="ts">
  import { onMount } from 'svelte';
  import { fade, slide } from 'svelte/transition';
  import { API } from '../lib/api';
  import { store } from '../lib/store.svelte';
  import { ICONS } from '../lib/constants';
  import type { ConflictEntry } from '../lib/types';
  import Skeleton from '../components/Skeleton.svelte';
  import BottomActions from '../components/BottomActions.svelte';
  import './WinnowingTab.css';

  import '@material/web/textfield/outlined-text-field.js';
  import '@material/web/chips/chip-set.js';
  import '@material/web/chips/filter-chip.js';
  import '@material/web/icon/icon.js';
  import '@material/web/divider/divider.js';
  import '@material/web/iconbutton/filled-tonal-icon-button.js';

  let conflicts = $state<ConflictEntry[]>([]);
  let loading = $state(true);
  let searchTerm = $state("");

  const L_W = $derived(store.L.winnowing || {});
  const L_C = $derived(store.L.common || {});

  function getFullPath(entry: ConflictEntry) {
    return `/${entry.partition}/${entry.relative_path}`;
  }

  async function loadData() {
    loading = true;
    try {
      conflicts = await API.getConflicts();
      if (store.conflicts.length !== conflicts.length) {
          store.loadConflicts();
      }
    } catch (e) {
      store.showToast(store.L.modules?.conflictError || "Failed to load", "error");
    } finally {
      loading = false;
    }
  }

  async function selectWinner(item: ConflictEntry, moduleId: string) {
    const idx = conflicts.findIndex(c => c.partition === item.partition && c.relative_path === item.relative_path);
    if (idx !== -1) {
      conflicts[idx].selected = moduleId;
      conflicts[idx].is_forced = true;
    }
    try {
      await API.setWinnowingRule(getFullPath(item), moduleId);
    } catch(e) {
      store.showToast("Failed to set rule", "error");
    }
  }

  let filteredConflicts = $derived(conflicts.filter(c => 
    getFullPath(c).toLowerCase().includes(searchTerm.toLowerCase())
  ));

  onMount(loadData);
</script>

<div class="winnow-page">
  <div class="search-box">
      <md-outlined-text-field
        placeholder={L_W.searchPlaceholder || "Search paths..."}
        value={searchTerm}
        oninput={(e: Event) => searchTerm = (e.target as HTMLInputElement).value}
        class="full-width-field"
      >
        <md-icon slot="leading-icon"><svg viewBox="0 0 24 24"><path d={ICONS.search} /></svg></md-icon>
      </md-outlined-text-field>
  </div>

  {#if loading}
    <div class="list-wrapper">
        {#each Array(4) as _}
            <div class="conflict-card skeleton-card">
               <Skeleton width="100%" height="100px" borderRadius="16px"/>
            </div>
        {/each}
    </div>
  {:else if conflicts.length === 0}
    <div class="clean-state" in:fade>
      <div class="clean-icon-circle">
          <md-icon class="clean-icon"><svg viewBox="0 0 24 24"><path d={ICONS.check} /></svg></md-icon>
      </div>
      <h3>{L_W.emptyTitle || 'All Clear'}</h3>
      <p>{L_W.emptyDesc || 'No conflicts detected.'}</p>
    </div>
  {:else}
    <div class="conflict-list">
      {#each filteredConflicts as item (getFullPath(item))}
        <div class="conflict-card" class:forced={item.is_forced} transition:slide={{ axis: 'y' }}>
          <div class="card-header">
            <md-icon class="file-icon"><svg viewBox="0 0 24 24"><path d={ICONS.description} /></svg></md-icon>
            <div class="path-info">
                <span class="path-label">{L_W.conflictPath || 'Conflict Path'}</span>
                <span class="path-text" title={getFullPath(item)}>{getFullPath(item)}</span>
            </div>
          </div>
          
          <md-divider></md-divider>

          <div class="card-body">
              <span class="selection-label">{L_W.selectProvider || 'Select Provider'}:</span>
              <md-chip-set>
                {#each item.contending_modules as modId}
                  <md-filter-chip 
                    label={modId}
                    selected={item.selected === modId}
                    onclick={() => selectWinner(item, modId)}
                    role="button" tabindex="0" onkeydown={() => {}}
                  ></md-filter-chip>
                {/each}
              </md-chip-set>
          </div>
        </div>
      {/each}
    </div>
  {/if}
</div>

<BottomActions>
    <div class="spacer"></div>
    <md-filled-tonal-icon-button 
      onclick={loadData} 
      disabled={loading}
      title={L_C.refresh || "Refresh"}
      role="button" tabindex="0" onkeydown={() => {}}
    >
      <md-icon><svg viewBox="0 0 24 24"><path d={ICONS.refresh} /></svg></md-icon>
    </md-filled-tonal-icon-button>
</BottomActions>