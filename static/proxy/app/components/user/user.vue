<template>

<div v-if="show_user">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="userName" :lead="userName"
      v-observe-visibility="visibilityChanged"
    >

      <h5 v-if="enroll_nwid">Device enroll network ID: {{ enroll_nwid }} </h5>

      <div v-if="user && !deleted">
          <b-btn variant="warning" :disabled="busy" v-on:click="delete_user">Delete user</b-btn>
          <b-btn variant="success" :disabled="busy" v-on:click="createDeviceEnrollNetwork()"
            v-if="!enroll_nwid"
            >Create device enroll network
          </b-btn>
          <b-btn variant="danger" :disabled="busy" v-on:click="deleteDeviceEnrollNetwork()"
            v-if="enroll_nwid"
            >Delete device enroll network
          </b-btn>

          <b-card
             title="Roles"
             tag="article"
             style="max-width: 20rem;"
             class="mb-2"
           >
            <b-btn variant="info" :disabled="busy" v-on:click="assign_role('friends')"
              v-if="!user.roles.includes('friends')"
              >Assign role "friends"
            </b-btn>
            <b-btn variant="info" :disabled="busy" v-on:click="assign_role('staff')"
              v-if="!user.roles.includes('staff')"
              >Assign role "staff"
            </b-btn>

            <h5>Assigned roles</h5>
            <b-list-group v-if="user.roles.length > 0">
              <b-list-group-item
                v-for="(role, index) in user.roles"
                v-bind:key="index"
              >
                <h5> {{ role }} </h5>
                  <b-btn variant="danger" :disabled="busy" v-on:click="revoke_role(role)"
                    >Revoke role " {{ role }} "
                  </b-btn>
              </b-list-group-item>
            </b-list-group>
          </b-card>
      </div>
      <div v-if="user && deleted">
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
    userName() {
      return this.name
    },
    show_user() {
      if (!this.user_regex) {
        return true
      }
      if (this.name.match(this.user_regex)) {
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
      user: null,
      enroll_nwid: "",
      enroll_controller: this.controller
    }
  },
  props: ["name", "controller", "creds", "user_regex"],
  methods: {
    visibilityChanged(changed) {
      if (changed && !this.user) {
        this.get_user()
      }
    },
    zt1_enroll_nw_template() {
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
    deleteDeviceEnrollNetwork() {
      this.busy = true
      axios
        .delete(this.$restApi + this.enroll_controller + "/network/" + this.enroll_nwid, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.get_user()
          if (this.user.name == this.creds.user.name) {
            this.$parent.$emit('load_user')
          }
        })
        .catch(error => {
          console.log(error)
          this.errored = true
        })
        .finally(() => {this.busy = false})
    },
    createDeviceEnrollNetwork() {
      this.busy = true
      new_nwconf = this.zt1_enroll_nw_template()
      new_nwconf.name = "Device Enroll Network " + this.user.name
      axios
        .post(this.$restApi + this.enroll_controller + "/network", {
          nwconf: new_nwconf,
          nwinfo: {"type": "device_enroll", "owner": this.user.name}
        },{
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.get_user()
          if (this.user.name == this.creds.user.name) {
            this.$parent.$emit('load_user')
          }
        })
        .catch(error => {
          console.log(error)
          this.errored = true
        })
        .finally(() => {this.busy = false})
    },
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
          if (['delete-user'].includes(method)) {
            this.deleted = true
          }
          if (['assign-user-role', 'revoke-user-role'].includes(method)) {
            this.user = response.data
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
    assign_role(role) {
      this.confirm_action = "assign-user-role"
      this.action_data = {name: this.user.name, role: role}
      this.busy = true
      return this.rpc(event, this.confirm_action, this.action_data)
    },
    revoke_role(role) {
      this.confirm_action = "revoke-user-role"
      this.action_data = {name: this.user.name, role: role}
      this.busy = true
      return this.rpc(event, this.confirm_action, this.action_data)
    },
    delete_user(event) {
      this.confirm_action = "delete-user"
      this.action_data = {name: this.user.name}
      this.request_confirmation = true
      this.busy = true
    },
    get_user () {
      axios
        .post(this.$restApi + this.controller + "/rpc/get-user", {name: this.name}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.user = response.data
          this.enroll_nwid = ""
          Object.keys(this.user.networks).forEach(function (nwid) {
            if (this.user.networks[nwid].type == "device_enroll") {
              this.enroll_nwid = nwid
              this.enroll_controller = this.user.networks[nwid].controller
            }
          }.bind(this))
        })
        .catch(error => {
          console.log(error)
          this.errored = true
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
    font-size: 1.5rem;
    font-weight: 300;
    line-height: 1.2;
    }
}
</style>
