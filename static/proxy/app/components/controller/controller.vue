<template>
<div>


  <div v-if="creating_network">

    <b-btn variant="info"
           v-on:click="cancelCreateNetwork()"
    >Cancel</b-btn>


    <b-jumbotron
                 header="Add Network"
                 lead="Enter network details:" >
      <div class="col-6">

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Network name</span>
          </div>
          <b-form-input
                        id="input-live"
                        type="text"
                        v-model="new_nwconf.name"
                        placeholder="Enter network name"
                        v-on:keyup.enter.native="createNetwork()"
                        :state="state_nwconf_name"
                        aria-describedby="input-live-help input-live-feedback"
          ></b-form-input>

          <b-input-group-append>
            <b-btn variant="success"
                   v-on:click="createNetwork()"
            >Create network</b-btn>
          </b-input-group-append>

          <b-form-invalid-feedback id="input-live-feedback">
            Enter at least 3 letters
          </b-form-invalid-feedback>

        </b-input-group>

      </div>

    </b-jumbotron>

  </div>


  <div>
    <div v-if="!creating_network">
      <b-btn variant="info"
             v-on:click="showCreateNetwork()"
      >Create</b-btn>

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
    </div>

  <b-alert class="col-6" :show="10" v-if="tokenExpiresIn < 3600"> Access token will expire in {{ tokenExpiresIn }} seconds </b-alert>

  <error-axios
    v-bind:err_resp="err_resp"
  >
  </error-axios>

  <div v-if="!creating_network">
    <div v-if="loading">
      <b-alert class="col-6" show > Searching ... </b-alert>
    </div>

    <div v-if="!loading && networks && networks.length > 0">
      <network
        v-for="(network, index) in networks"
        v-bind:key="index"
        v-bind:network="network"
        v-bind:controller="controller"
        v-bind:creds="creds"
        v-bind:nw_regex="nw_regex"
      >
      </network>
    </div>

    <div v-if="!loading && networks && networks.length == 0">
        <b-alert class="col-6" show> No networks found ... </b-alert>
    </div>
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
      new_nwconf: null,
      check_state_nwconf_name: false,
      creating_network: false
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
      return new RegExp(this.network_filter, 'ig')
    },
    state_nwconf_name() {
      if (!this.check_state_nwconf_name) {
        return null
      }
      return this.new_nwconf.name.length > 2 ? true : false
    }
  },
  mounted () {
    this.network_filter = this.nw_filter
    this.getNetworks()
  },
  methods: {
    clear() {
      this.loading = true
      this.err_resp = null
      this.alert_msg = ""
    },
    zt1_nw_template() {
      return {
        "authTokens":   [{
                }],
        "capabilities": [],
        "enableBroadcast":      false,
        "ipAssignmentPools":    [],
        "mtu":  2800,
        "multicastLimit":       32,
        "name": "",
        "private":      true,
        "remoteTraceLevel":     0,
        "remoteTraceTarget":    null,
        "routes":       [],
        "rules":        [{
                        "not":  false,
                        "or":   false,
                        "type": "ACTION_DROP"
                }],
        "tags": [],
        "v4AssignMode": {
                "zt":   false
        },
        "v6AssignMode": {
                "6plane":       false,
                "rfc4193":      false,
                "zt":   false
        }
      }
    },
    cancelCreateNetwork() {
      this.creating_network = false
    },
    showCreateNetwork() {
      this.new_nwconf = this.zt1_nw_template()
      this.creating_network = true
      this.check_state_nwconf_name = false
    },
    createNetwork() {
      if (!this.new_nwconf.name) {
        this.check_state_nwconf_name = true
        return
      }
      this.check_state_nwconf_name = false
      axios
        .post(this.$restApi + this.controller + "/network", {
          nwconf: this.new_nwconf,
          nwinfo: {"type": "test"}
        },{
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
        })
        .catch(error => {
          console.log(error)
          this.errored = true
        })
        .finally(() => this.getNetworks())
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
        .finally(() => {
          this.loading = false
          this.creating_network = false
        })
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
