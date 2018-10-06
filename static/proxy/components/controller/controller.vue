<template>
<div>

<!--

  <div>

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="network-name">
          Network ID or Name:
        </span>
      </div>

      <b-form-input 
                    type="text"
                    v-model="controller"
                    placeholder="Enter network ID or name"
                    v-on:keyup.enter.native="getNetworks"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="succes"
               v-on:click="getNetworks"
        >List Networks</b-btn>
      </b-input-group-append>
    </b-input-group>

    </b-input-group>

  </div>
  <b-alert class="col-6" :show="need_controller_name"> Please enter controller name </b-alert>
  <b-alert class="col-6" :show="need_username"> Please enter username </b-alert>
  <b-alert class="col-6" :show="need_password"> Please enter password </b-alert>
  <b-alert class="col-6" :show="need_oath"> Please enter access token </b-alert>
  <b-alert class="col-6" :show="no_such_controller"> No such controller found </b-alert>

  <b-alert class="col-6" :show="need_token"> Access token is missing ?? </b-alert>
  <b-alert class="col-6" :show="have_invalid_token"> Access token is invalid ?? </b-alert>


  <section v-if="errored">
    <i v-if="error"> {{ error }} </i>
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-else>
    <div v-if="loading">
      <b-alert class="col-6" show > Searching ... </b-alert>
    </div>
    <div v-else-if="networks && networks.length > 0">

      <network
        v-for="nwid, index in networks"
        v-bind:id="nwid"
        v-bind:controller="controller"
        v-bind:creds="creds"
        v-bind:nw_filter="nw_filter"
      >
      </network>

    </div>

    <div v-else-if="networks">
        <b-alert class="col-6" show> No networks found ... </b-alert>
    </div>

  </section>
-->

      <network
        v-for="nwid, index in networks"
        v-bind:id="nwid"
        v-bind:controller="controller"
        v-bind:creds="creds"
        v-bind:nw_filter="nw_filter"
      >
      </network>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      info: null,
      loading: false,
      errored: false,
      error: null,
      need_controller_name: false,
      need_username: false,
      need_password: false,
      need_oath: false,
      need_token: false,
      have_invalid_token: false,
      no_such_controller: false,
      controller_status: null,
      controller: "",
      networks: [],
      creds: {username: "", password: "", oath: "", token: ""},
    }
  },
  props: ["controller", "creds", "nw_filter"],
  mounted () {
    this.getNetworks()
  },
  methods: {
    clear() {
      this.need_controller_name = false
      this.need_username = false
      this.need_password = false
      this.need_oath = false
      this.no_such_controller = false
      controller_status: null,
      this.error = null
    },
    getNetworks (event) {
      if ((this.controller == null) || (this.controller == "")) {
        this.need_controller_name = true
        return
      }
      if ((this.creds == null) || (this.creds.token == null)) {
        this.need_token = true
        return
      }
      if (!this.creds.token.id) {
        this.have_invalid_token = true
        return
      }

      console.log(this.creds)
      // TODO check for expiration of token
      // move token functions to generic object or VUEX

      this.clear()
      axios
        .get("/api/1.0/proxy/" + this.controller + "/network", {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.networks = response.data
          console.log(this.networks)
        }).catch(error => {
          if ((error.response) && (error.response.status == 404)) {
            this.no_such_controller = true
          }
          else {
            console.log(error)
            this.errored = true
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
