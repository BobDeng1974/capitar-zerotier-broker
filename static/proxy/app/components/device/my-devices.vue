<template>
<div>

  <div v-if="adding_device">

    <b-btn variant="info"
           v-on:click="cancelAddDevice()"
    >Cancel</b-btn>


    <b-jumbotron 
               header="Add device"
               lead="Enter device details:" >
      <div class="col-6">

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Device ID</span>
          </div>
          <b-form-input 
                        type="text"
                        v-model="newdevice.id"
                        placeholder="Enter device ID"
                        v-on:keyup.enter.native="addDevice()"
          ></b-form-input>
        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Device name</span>
          </div>
          <b-form-input 
                        type="text"
                        v-model="newdevice.name"
                        placeholder="Enter device name"
                        v-on:keyup.enter.native="addDevice()"
          ></b-form-input>
        </b-input-group>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Device description</span>
          </div>
          <b-form-input 
                        type="text"
                        v-model="newdevice.description"
                        placeholder="Enter device description"
                        v-on:keyup.enter.native="addDevice()"
          ></b-form-input>

          <b-input-group-append>
            <b-btn variant="success"
                   v-on:click="addDevice()"
            >Add device</b-btn>
          </b-input-group-append>
        </b-input-group>

      </div>

    </b-jumbotron>



  </div>
  <div v-if="!adding_device">

    <b-btn variant="info"
           v-on:click="showAddDevice()"
    >Add device</b-btn>

    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="device_filter">Search device</span>
      </div>
      <b-form-input
                    type="text"
                    v-model="device_filter"
                    placeholder="Enter part of device id or name"
                    v-on:keyup.enter.native="getDevices()"
      ></b-form-input>
      <b-input-group-append>
        <b-btn variant="info"
               v-on:click="getDevices()"
        >Search</b-btn>
      </b-input-group-append>

    </b-input-group>

  </div>
  <div>

  <b-alert class="col-6" :show="10" v-if="tokenExpiresIn < 3600"> Access token will expire in {{ tokenExpiresIn }} seconds </b-alert>

  <error-axios
    v-bind:err_resp="err_resp"
  >
  </error-axios>

  </div>
  <div v-if="!adding_device">

    <div v-if="loading">
      <b-alert class="col-6" show > Searching ... </b-alert>
    </div>

    <div v-if="!loading && devices && Object.keys(devices).length > 0">
      <device
        v-for="(device, id) in devices"
        v-bind:key="id"
        v-bind:id="id"
        v-bind:creds="creds"
        v-bind:controller="controller"
        v-bind:device_regex="device_regex"
      >
      </device>
    </div>

    <div v-if="!loading && devices && Object.keys(devices).length == 0">
        <b-alert class="col-6" show> No devices found ... </b-alert>
    </div>
  </div>


</div>
</template>

<script>

module.exports = {
  data () {
    return {
      adding_device: false,
      info: null,
      loading: false,
      err_resp: null,
      alert_msg: "",
      devices: null,
      newdevice: null,
      device_filter: ""
    }
  },
  props: ["controller", "creds"],
  computed: {
    // Number of seconds the token will expire in, if expire time is set
    tokenExpiresIn() {
      if (!this.creds.token || this.creds.token.expires == 0) {
        return null
      }
      return this.creds.token.expires - Math.floor(Date.now() / 1000)
    },
    device_regex () {
      if (!this.device_filter) {
        return null
      }
      return new RegExp(this.device_filter, 'ig')
    }
  },
  mounted () {
    this.devices = this.creds.user.devices
  },
  methods: {
    clear() {
      this.loading = true
      this.err_resp = null
      this.alert_msg = ""
    },
    showAddDevice() {
      this.newdevice = {id: "", name: "", description: ""}
      this.adding_device = true
    },
    cancelAddDevice() {
      this.adding_device = false
    },
    addDevice() {
      axios
        .post(this.$restApi + this.controller + "/rpc/add-own-device", {
          device: this.newdevice}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.devices[this.newdevice.id] = this.newdevice
          this.$emit('load_user')
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
        .finally(() => this.adding_device = false)
    },
    getDevices (event) {
      this.clear()
      axios
        .post(this.$restApi + this.controller + "/rpc/get-devices", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.devices = response.data
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
