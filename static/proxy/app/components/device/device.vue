<template>

<div v-if="show_device">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="device_header" :lead="device_lead" >
      <p>{{ device.description }}</p>
      <div v-if="!deleted && !busy">

          <b-btn variant="success" :disabled="busy" v-on:click="enroll_device"
            v-if="!device.enrolled && enroll_nwid"
            >Enroll</b-btn>

          <b-btn variant="warning" :disabled="busy" v-on:click="delete_device"
            >Delete</b-btn>

      </div>

      <div v-if="deleted">
          <i>Deleted</i>
      </div>

      <div v-if="enrolling">
          <h5><b>Important:</b>
            before continueing, your device must have joined your personal
            device enroll network: {{ enroll_nwid }} </h5>
      </div>

      <div v-if="request_confirmation">
        <b-btn variant="info" v-on:click="cancel_confirm">No, cancel</b-btn>
        <b-btn variant="warning" v-on:click="confirm">Yes, {{ confirm_action }}</b-btn>
      </div>

    </b-jumbotron>

  </section>

  <error-axios
    v-bind:err_resp="err_resp"
  ></error-axios>


</div>

</template>

<script>

module.exports = {

  computed: {
    device_header() {
      if (!this.device.enrolled) {
        return this.device.id
      }
      return this.device.id + " (enrolled)"
    },
    device_lead() {
      return this.device.name
    },
    show_device() {
      if (!this.device) {
        return false
      }
      if (!this.device_regex) {
        return true
      }
      if (this.device.id.match(this.device_regex)) {
        return true
      }
      if (this.device.name.match(this.device_regex)) {
        return true
      }
      return false
    }
  },
  data () {
    return {
      info: null,
      loading: true,
      errored: false,
      confirm_action: "",
      action_controller: null,
      action_data: null,
      request_confirmation: false,
      deleted: false,
      busy: false,
      device: null,
      enroll_nwid: "",
      enrolling: false,
      err_resp: null
    }
  },
  props: ["id", "controller", "creds", "device_regex"],
  methods: {
    set_enroll_network() {
      Object.keys(this.creds.user.networks).forEach(function (nwId) {
        if (this.creds.user.networks[nwId].type == "device_enroll") {
          this.enroll_nwid = nwId
          this.enroll_controller = this.creds.user.networks[nwId].controller
        }
      }.bind(this))
    },
    clear() {
      this.err_resp = null
      this.alert_msg = ""
    },
    confirm(event) {
      this.request_confirmation = false
      controller = this.action_controller || this.controller
      return this.rpc(event, controller, this.confirm_action, this.action_data)
    },
    cancel_confirm(event) {
      this.request_confirmation = false
      this.confirm_action = ''
      this.busy = false
      this.enrolling = false
    },
    rpc(event, controller, method, data) {
      this.clear()
      this.busy = true
      axios
        .post(this.$restApi + controller + "/rpc/" + method,
          data, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          console.log(response)
          if (['delete-own-device'].includes(method)) {
            this.deleted = true
            this.$parent.$emit('load_user')
          }
          if (['enroll-own-device'].includes(method)) {
            this.enrolling = false
            this.$parent.$emit('load_user')
          }
        }).catch(error => {
          if (['enroll-own-device'].includes(method)) {
            this.enrolling = false
          }
          if ((error.response) && error.response.status ) {
            this.err_resp = error.response
          }
          else {
            console.log("undefined error: ", error)
          }
        })
        .finally(() => {
          this.busy = false
        })
    },
    delete_device(event) {
      this.clear()
      this.action_controller = this.controller
      this.confirm_action = "delete-own-device"
      this.action_data = {id: this.device.id}
      this.request_confirmation = true
      this.busy = true
    },
    enroll_device(event) {
      this.clear()
      if (!this.enroll_nwid) {
        console.log("No enroll network")
        this.err_resp.statusText = "No enroll network"
        return
      }
      this.confirm_action = "enroll-own-device"
      this.action_controller = this.enroll_controller
      this.action_data = {member: this.device.id, network: this.enroll_nwid}
      this.request_confirmation = true
      this.busy = true
      this.enrolling = true
    }
  },
  mounted () {
    this.device = this.creds.user.devices[this.id]
    this.set_enroll_network()
    /*
    axios
      .post(this.$restApi + this.controller + "/rpc/get-device", {id: this.device.id}, {
        headers: {'X-ZTC-Token': this.creds.token.id }
      })
      .then(response => {
        this.device = response.data
      })
      .catch(error => {
        console.log(error)
        this.errored = true
      })
      .finally(() => this.loading = false)
    */
  }
}
</script>

<style>
.jumbotron {
    //background-color: #ffe;
}
.display-3 {
    font-size: 1.5rem;
    font-weight: 300;
    line-height: 1.2;
    }
}
</style>
