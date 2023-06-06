<script lang="ts">
  import type { PageData } from "./$types";

  export let data: PageData;
</script>

{#if data.user?.name}
  <div>
    <p>Logged in as {data.user?.name}</p>
  </div>
  <form action="/auth/logout" method="POST">
    <button>Logout</button>
  </form>
{:else}
  <div>
    <p>Not logged in</p>
  </div>
  <div>
    <a href="/auth/login/google">Login with Google</a>
  </div>
{/if}

<slot />
