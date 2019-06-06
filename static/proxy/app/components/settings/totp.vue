<template>

<div v-if="show_totp">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="totp_header" :lead="totp_lead" >
      <p>{{ totp.description }}</p>
      <div v-if="!deleted && !busy">

          <b-btn variant="warning" :disabled="busy" v-on:click="delete_totp"
            >Delete</b-btn>

      </div>

      <div v-if="deleted">
          <i>Deleted</i>
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
    totp_header() {
      return this.totp.name
    },
    device_lead() {
      return ""
    },
    show_totp() {
      if (!this.totp) {
        return false
      }
      if (!this.totp_regex) {
        return true
      }
      if (this.totp.name.match(this.totp_regex)) {
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
      enroll_nwid: "",
      enrolling: false,
      err_resp: null
    }
  },
  props: ["totp", "controller", "creds", "totp_regex"],
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
      this.enrolling = false
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
          if (['delete-totp'].includes(method)) {
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
    delete_totp(event) {
      this.clear()
      this.confirm_action = "delete-totp"
      this.action_data = {issuer: this.totp.name}
      this.request_confirmation = true
      this.busy = true
    },
  },
  mounted () {
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
