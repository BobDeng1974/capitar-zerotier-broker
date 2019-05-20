<template>
<div>

<b-navbar class="navbar navbar-dark bg-warning navbar-expand-md navbar-capitar"
          toggleable="md" type="dark" variant="warning">

  <b-navbar-toggle target="nav_collapse"></b-navbar-toggle>

  <b-navbar-brand href="#">
      <img src="/static/deps/logos/capitar-logo-inverse.png"
           class="d-inline-block align-top capitar-logo">
  </b-navbar-brand>

  <b-collapse is-nav id="nav_collapse" v-if="creds.ready">
    <b-navbar-nav>
      <!--
      <b-nav-item class="navbar-link" href="#">Link</b-nav-item>
      <b-nav-item href="#" disabled>Disabled</b-nav-item>
      -->
      <b-nav-item class="navbar-link" @click="$emit('deviceadmin')">My Devices</b-nav-item>
      <b-nav-item class="navbar-link" @click="$emit('networkadmin')">My Networks</b-nav-item>
      <b-nav-item class="navbar-link" @click="$emit('useradmin')">User Admin</b-nav-item>
    </b-navbar-nav>

    <!-- Right aligned nav items -->
    <b-navbar-nav class="ml-auto">

      <b-nav-form>
        <b-form-input size="sm" class="mr-sm-2" type="text" placeholder="Search"/>
        <b-button size="sm" class="my-2 my-sm-0" type="submit">Search</b-button>
      </b-nav-form>

      <!--b-nav-item-dropdown text="Lang" right>
        <b-dropdown-item href="#">EN</b-dropdown-item>
        <b-dropdown-item href="#">ES</b-dropdown-item>
        <b-dropdown-item href="#">RU</b-dropdown-item>
        <b-dropdown-item href="#">FA</b-dropdown-item>
      </b-nav-item-dropdown-->

      <b-nav-item-dropdown right>
        <!-- Using button-content slot -->
        <template slot="button-content">
          <em>{{ creds.username }}</em>
        </template>
        <b-dropdown-item @click="$emit('settings_gui_user')">Settings</b-dropdown-item>
        <b-dropdown-item @click="$emit('logout')">Signout</b-dropdown-item>
      </b-nav-item-dropdown>
    </b-navbar-nav>

  </b-collapse>
</b-navbar>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
    }
  },
  props: ["controller", "creds", "nw_filter"],
  computed: {
  },
  methods: {
  }
}

</script>

<style scoped>
.bg-warning {
    background-color: #eb5814 !important;
}

.navbar-capitar {
    border-style: unset;
    height: 52px;
    font-size: 12px;
    font-weight: 700;
    text-transform: uppercase;
}

.capitar-logo {
    float: left;
    height: 52px;
}

.navbar-dark .navbar-nav .nav-link {
	color: rgba(255,255,255,255);
}

.navbar-dark .navbar-nav .nav-link.disabled {
	color: rgba(255,255,255,0.25);
}

</style>
