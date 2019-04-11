<template>

<div v-if="show_device">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="device.id" :lead="device.name" >
      <p>{{ device.description }}</p>
      <div v-if="!deleted">
          <b-btn variant="warning" :disabled="busy" v-on:click="delete_device">Delete</b-btn>
      </div>
      <div v-else="deleted">
          <i>Deleted</i>
      </div>

      <div v-if="request_confirmation">
        <b-btn variant="info" v-on:click="cancel_confirm">No, cancel</b-btn>
        <b-btn variant="warning" v-on:click="confirm">Yes, {{ confirm_action }}</b-btn>
      </div>

    </b-jumbotron>

  </section>

</div>

</template>

<script>

module.exports = {

  computed: {
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
      action_data: null,
      request_confirmation: false,
      deleted: false,
      busy: false,
      device: null,
    }
  },
  props: ["id", "controller", "creds", "device_regex"],
  methods: {
    clear() {
      this.err_resp = null
      this.alert_msg = ""
    },
    confirm(event) {
      this.request_confirmation = false
      return this.rpc(event, this.confirm_action, this.action_data)
    },
    cancel_confirm(event) {
      this.request_confirmation = false
      this.confirm_action = ''
      this.busy = false
    },
    rpc(event, method, data) {
      this.clear()
      this.busy = true
      axios
        .post(this.$restApi + this.controller + "/rpc/" + method,
          data, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          console.log(response)
          if (['delete-own-device'].includes(method)) {
            this.deleted = true
            this.$parent.$emit('load_user')
          }
        }).catch(error => {
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
      this.confirm_action = "delete-own-device"
      this.action_data = {id: this.device.id}
      this.request_confirmation = true
      this.busy = true
    }
  },
  mounted () {
    this.device = this.creds.user.devices[this.id]
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
