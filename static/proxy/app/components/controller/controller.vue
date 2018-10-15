<template>
<div>

  <div>

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="nw_filter">Search network</span>
      </div>
      <b-form-input
                    type="text"
                    v-model="network_filter"
                    placeholder="Enter part of ID or name"
                    v-on:keyup.enter.native="getNetworks()"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="success"
               v-on:click="getNetworks()"
        >Search</b-btn>
      </b-input-group-append>

    </b-input-group>

  <b-alert class="col-6" :show="10" v-if="tokenExpiresIn < 3600"> Access token will expire in {{ tokenExpiresIn }} seconds </b-alert>

  <error-axios
    v-bind:err_resp="err_resp"
  >
  </error-axios>

  <div v-if="loading">
    <b-alert class="col-6" show > Searching ... </b-alert>
  </div>

  <div v-else-if="networks && networks.length > 0">
    <network
      v-for="nwid, index in networks"
      v-bind:id="nwid"
      v-bind:controller="controller"
      v-bind:creds="creds"
      v-bind:nw_regex="nw_regex"
    >
    </network>
  </div>

  <div v-else-if="networks">
      <b-alert class="col-6" show> No networks found ... </b-alert>
  </div>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      info: null,
      loading: true,
      err_resp: null,
      alert_msg: "",
      networks: [],
      network_filter: "",
    }
  },
  props: ["controller", "creds", "nw_filter"],
  computed: {
    // Number of seconds the token will expire in, if expire time is set
    tokenExpiresIn() {
      if (!this.creds.token || this.creds.token.expires == 0) {
        return null
      }
      return this.creds.token.expires - Math.floor(Date.now() / 1000)
    },
    nw_regex () {
      if (!this.network_filter) {
        return null
      }
      return new RegExp(this.network_filter, 'g')
    }
  },
  mounted () {
    this.network_filter = this.nw_filter
    this.getNetworks()
  },
  methods: {
    clear() {
      this.err_resp = null
      this.alert_msg = ""
    },
    getNetworks (event) {
      this.clear()
      axios
        .get(this.$restApi + this.controller + "/network", {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.networks = response.data
        }).catch(error => {
          if ((error.response) && (error.response.status == 404)) {
            this.alert_msg = "No such controller found"
          }
          if ((error.response) && error.response.status ) {
            this.err_resp = error.response
          }
          else {
            console.log("undefined error: ", error)
          }
        })
        .finally(() => this.loading = false)
    }
  }
}
</script>

<style>
.jumbotron {
    //background-color: #ffe;
}
.display-3 {
    font-size: 2.5rem;
    font-weight: 300;
    line-height: 1.2;
    }
}
</style>
