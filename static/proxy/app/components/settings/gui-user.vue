<template>
<div>

  <h2>Settings</h2>

  <div v-if="confirming_totp">

    <b-btn variant="info"
           v-on:click="cancelConfirmTotp()"
    >Cancel</b-btn>

    <b-jumbotron 
               header="Configure and confirm TOTP"
               lead="Use e.g. Google Authenticator app to configure and confirm:" >

      <div class="col-6">

        <b-list-group>
          <b-list-group-item>Issuer: {{ newtotp.issuer }} </b-list-group-item>
          <b-list-group-item>Type: {{ newtotp.type }} </b-list-group-item>
          <b-list-group-item>Algorithm: {{ newtotp.algorithm }} </b-list-group-item>
          <b-list-group-item>Encoding: base32 </b-list-group-item>
          <b-list-group-item>Secret: {{ newtotp.secret }} </b-list-group-item>
          <b-list-group-item>Example: oathtool -b --totp=sha1 {{ newtotp.secret }} </b-list-group-item>
        </b-list-group>

        <div class="mx-auto" style="width: 256px;">
          <qr-code :text="newtotp.url" :size=256 ></qr-code>
        </div>

        <br>

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Auth code</span>
          </div>
          <b-form-input 
                        type="text"
                        v-model="confirmtotp.confirm_code"
                        placeholder="Enter generated auth code"
                        v-on:keyup.enter.native="confirmTotp()"
          ></b-form-input>
        </b-input-group>

        <b-input-group-append>
            <b-btn variant="success"
                   v-on:click="confirmTotp()"
            >Confirm TOTP</b-btn>
          </b-input-group-append>
        </b-input-group>

      </div>

    </b-jumbotron>

  </div>

  <div v-if="adding_totp">

    <b-btn variant="info"
           v-on:click="cancelAddTotp()"
    >Cancel</b-btn>

    <b-jumbotron 
               header="Add TOTP"
               lead="Enter details:" >
      <div class="col-6">

        <b-input-group>
          <div class="input-group-prepend w-25">
            <span class="input-group-text w-100" id="id">Issuer</span>
          </div>
          <b-form-input 
                        type="text"
                        v-model="newtotp.issuer"
                        placeholder="Enter issuer"
                        v-on:keyup.enter.native="addTotp()"
          ></b-form-input>
        </b-input-group>

        <b-input-group-append>
            <b-btn variant="success"
                   v-on:click="addTotp()"
            >Add TOTP</b-btn>
          </b-input-group-append>
        </b-input-group>

      </div>

    </b-jumbotron>

  </div>
  <div v-if="!adding_totp && !confirming_totp">

    <b-btn variant="info"
           v-on:click="showAddTotp()"
    >Add TOTP</b-btn>
  </div>

  <h3> 2Factor authentication (TOTP)</h3>

  <div v-if="creds.user && creds.user.otpwds.length >0">
    <b-input-group>
      <div class="input-group-prepend w-25">
        <span class="input-group-text w-100" id="totp_filter">Filter totp</span>
      </div>
      <b-form-input
                    type="text"
                    v-model="totp_filter"
                    placeholder="Enter part of name (issuer)"
      ></b-form-input>
    </b-input-group>

    <totp
      v-for="(totp, index) in creds.user.otpwds"
      v-bind:key="index"
      v-bind:totp="totp"
      v-bind:creds="creds"
      v-bind:controller="controller"
      v-bind:totp_regex="totp_regex"
    >
    </totp>

  </div>

  <div v-if="creds.user && creds.user.otpwds.length == 0">
    <b-alert class="col-6" show> No totps found ... </b-alert>
  </div>

</div>
</template>

<script>

module.exports = {
  data () {
    return {
      loading: false,
      err_resp: null,
      alert_msg: "",
      totp_filter: "",
      adding_totp: false,
      confirming_totp: false,
      newtotp: {issuer: "", type:"", algorithm: "", secret: "", url: ""},
      confirmtotp: {issuer: "", confirm_code: ""}
    }
  },
  props: ["controller", "creds"],
  computed: {
    totp_regex () {
      if (!this.totp_filter) {
        return null
      }
      return new RegExp(this.totp_filter, 'ig')
    }
  },
  mounted () {
  },
  methods: {
    clear() {
      this.loading = true
      this.err_resp = null
      this.alert_msg = ""
    },
    showAddTotp() {
      this.newtotp = {issuer: "", type:"", algorithm: "", secret: "", url: ""}
      this.adding_totp = true
    },
    cancelAddTotp() {
      this.adding_totp = false
    },
    addTotp() {
      axios
        .post(this.$restApi + this.controller + "/totp",
        this.newtotp, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.newtotp = response.data
          this.confirmtotp.issuer = this.newtotp.issuer
          this.confirmtotp.confirm_code = ""
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
          this.confirming_totp = true
          this.adding_totp = false
        })
    },
    cancelConfirmTotp() {
      this.confirming_totp = false
      this.$emit('load_user')
    },
    confirmTotp() {
      axios
        .post(this.$restApi + this.controller + "/totp",
        this.confirmtotp, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        }).then(response => {
          this.newtotp = response.data
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
        .finally(() => this.confirming_totp = false)
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
