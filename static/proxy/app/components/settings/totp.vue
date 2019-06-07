<template>

<div v-if="show_totp">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="totp_header" :lead="totp_lead" >
      <div v-if="!deleted && !busy">

          <b-btn variant="warning" :disabled="busy" v-on:click="delete_totp"
            >Delete</b-btn>

          <b-btn variant="success" :disabled="busy" v-on:click="activate_totp"
            v-if="!totp.active"
            >Activate</b-btn>
          <b-btn variant="warning" :disabled="busy" v-on:click="deactivate_totp"
            v-if="totp.active"
            >De-activate</b-btn>
          <b-btn v-if="!verified" variant="info" :disabled="busy" v-on:click="verify_totp"
            >Verify</b-btn>
          <b-btn v-if="verified" variant="success" :disabled="busy" v-on:click="verify_totp"
            >Verified OK!</b-btn>

      </div>

      <div v-if="deleted">
          <i>Deleted</i>
      </div>

      <div v-if="request_confirmation">
        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Auth code (To skip validation enter: 000000)</span>
          </div>
          <b-form-input
             v-if="show_confirm_code"
             type="text"
             v-model="action_data.confirm_code"
             placeholder="Enter auth code for validation"
             v-on:keyup.enter.native="confirm()"
          ></b-form-input>
        </b-input-group>

        <b-btn variant="info" v-on:click="cancel_confirm">No, cancel</b-btn>
        <b-btn v-if="!confirm_danger()" variant="warning" v-on:click="confirm">Yes, {{ confirm_action }}</b-btn>
        <b-btn v-if="confirm_danger()" variant="danger" v-on:click="confirm">Yes, {{ confirm_action }}</b-btn>
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
    totp_lead() {
      if (!this.totp.active) {
        return "(inactive)"
      }
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
      err_resp: null,
      verified: null,
    }
  },
  props: ["totp", "controller", "creds", "totp_regex"],
  methods: {
    clear() {
      this.err_resp = null
      this.alert_msg = ""
    },
    confirm_danger() {
      if (['delete-totp'].includes(this.confirm_action)) {
        return true
      }
      return false
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
          if (method == "verify-totp") {
            this.verified = response.data.verified
          }
          if (['delete-totp'].includes(method)) {
            this.deleted = true
            this.$parent.$emit('load_user')
          }
          if (['activate-totp', 'deactivate-totp'].includes(method)) {
            this.$parent.$emit('load_user')
          }
        }).catch(error => {
          if (method == "verify-totp") {
            this.verified = false
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
    delete_totp(event) {
      this.clear()
      this.confirm_action = "delete-totp"
      this.action_data = {issuer: this.totp.name, confirm_code:""}
      this.request_confirmation = true
      this.busy = true
    },
    activate_totp(event) {
      this.clear()
      this.confirm_action = "activate-totp"
      this.action_data = {issuer: this.totp.name, confirm_code:""}
      this.request_confirmation = true
      this.busy = true
    },
    deactivate_totp(event) {
      this.clear()
      this.confirm_action = "deactivate-totp"
      this.action_data = {issuer: this.totp.name, confirm_code:""}
      this.request_confirmation = true
      this.busy = true
    },
    verify_totp(event) {
      this.clear()
      this.confirm_action = "verify-totp"
      this.action_data = {issuer: this.totp.name, confirm_code:""}
      this.request_confirmation = true
      this.busy = true
    },
    show_confirm_code() {
      if (["verify-totp", "activate-totp", "deactivate-totp"].includes(
       this.confirm_action)) {
        return true
      }
      return false
    }
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
