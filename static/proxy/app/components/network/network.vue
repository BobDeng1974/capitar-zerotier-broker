<template>

<div v-if="show_network">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="nw.name" :lead="nw.id"
      v-observe-visibility="visibilityChanged"
    >
      <b-container>
        <b-row>
          <b-col>
            <h5> {{ nw.description }} </h5>
            <b-btn variant="info" v-on:click="showAddDevice()" v-if="!adding_device && !deleting_network"
            >Add Device</b-btn>
            <b-btn variant="warning" v-on:click="show_delete_network()" v-if="!adding_device && !deleting_network && creds.user.roles.includes('ops')"
            >Delete network</b-btn>

           <div v-if="deleting_network">
             <b-btn variant="info" v-on:click="cancel_delete_network()">No, cancel</b-btn>
             <b-btn variant="danger" v-on:click="delete_network()">Yes, delete</b-btn>
           </div>

            <div v-if="adding_device">

              <b-form-select v-model="selected_device" class="mb-3">
                <option :value="null" disabled>-- Please select device --</option>
                <option
                  v-for="(device, id) in creds.user.devices"
                  v-bind:key="id"
                  v-bind:value="id"
                  v-bind:disabled="Object.keys(nw_members).includes(id) || !device.enrolled"
                > {{ device.id }} : {{ device.name }}
                </option>
              </b-form-select>
              <b-btn variant="info" v-on:click="cancelAddDevice()"
              >Cancel</b-btn>
              <b-btn variant="success"
                v-on:click="addDevice(creds.user.devices[selected_device])"
                v-if="selected_device"
              >Add Device</b-btn>

            </div>

          </b-col>
          <b-col>

            <h4>Members</h4>
              <b-list-group :key="nw_member_seq">
                <b-list-group-item
                  v-for="(device, id) in nw_members"
                  v-bind:key="device.id"
                 >
                   <b-container>
                     <b-row>

                       <b-col> <h5>{{ device.id }}</h5>
                       </b-col>

                       <b-col v-if="Object.keys(creds.user.devices).includes(id) || creds.user.roles.includes('ops')">
                         <b-btn variant="success" v-on:click="authorize_nw_member(device)"
                           v-if="device.revision && !device.authorized"
                         >Authorize</b-btn>
                         <b-btn variant="warning" v-on:click="deauthorize_nw_member(device)"
                           v-if="device.revision && device.authorized"
                         >Deauthorize</b-btn>
                       </b-col>
                       <b-col v-else>
                       </b-col>

                       <b-col v-if="Object.keys(creds.user.devices).includes(id)">
                         <h5>{{ creds.user.devices[id].name }}</h5>
                         ( {{ creds.user.devices[id].description }} )
                       </b-col>
                       <b-col v-else>
                         unkown
                       </b-col>

                       <b-col>
                         revision: {{ device.revision }}
                       </b-col>

                     </b-row>
                   </b-container>

                 </b-list-group-item>
              </b-list-group>

          </b-col>
        </b-row>
      </b-container>
    </b-jumbotron>

  </section>

</div>

</template>

<script>

module.exports = {
  computed: {
    show_network() {
      if (!this.nw) {
        return false
      }
      if (!this.nw.id) {
        return false
      }
      if (!this.nw_regex) {
        return true
      }
      if (this.nw.id.match(this.nw_regex)) {
        return true
      }
      if (!this.nw.name) {
        return false
      }
      if (this.nw.name.match(this.nw_regex)) {
        return true
      }
      return false
    }
  },
  data () {
    return {
      selected_device: null,
      adding_device: false,
      info: null,
      errored: false,
      nw: this.network,
      nw_members: {},
      nw_member_seq: 1,
      requested_members: false,
      system_network: true,
      user_network: null,
      deleting_network: false
    }
  },
  props: ["network", "index", "networks", "controller", "creds", "nw_regex"],
  mounted () {
    if (!this.nw.system_network) {
      this.system_network = false
    } else {
      this.system_network = true
    }
    if (!this.nw.name) {
      this.get_nw()
    }
  },
  methods: {
    visibilityChanged(changed) {
      if (changed && !this.requested_members) {
        this.get_nw_members()
      }
    },
    nw_member_seq_inc() {
      this.nw_member_seq++
      return this.nw_member_seq
    },
    showAddDevice() {
      this.adding_device = true
    },
    cancelAddDevice() {
      this.adding_device = false
    },
    addDevice(device) {
      this.authorize_nw_member(device)
      this.adding_device = false
    },
    show_delete_network() {
      this.deleting_network = true
    },
    cancel_delete_network() {
      this.deleting_network = false
    },
    delete_network() {
      if (!this.system_network) {
        path = "/own_network/"
      } else {
        path = "/network/"
      }
      axios
        .delete(this.$restApi + this.controller + path + this.nw.id, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw = null
          this.deleting_network = false
	  this.$parent.$emit('load_user')
        })
        .catch(error => {
          console.log(error)
          this.deleting_network = false
        })
    },
    get_nw() {
      if (!this.system_network) {
        path = "/own_network/"
      } else {
        path = "/network/"
      }
      axios
        .get(this.$restApi + this.controller + path + this.nw.id, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw = response.data
          this.nw.system_network = this.system_network
        })
        .catch(error => {
          console.log(error)
        })
    },
    get_nw_members() {
      this.requested_members = true
      if (!this.system_network) {
        path = "/own_network/" + this.nw.id + "/member"
      } else {
        path = "/network/" + this.nw.id + "/member"
      }
      axios
        .get(this.$restApi + this.controller + path, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw_members = {}
          response.data.forEach(function (deviceId) {
            device = {id: deviceId, revision: 0}
            this.nw_members[deviceId] = device
            this.get_nw_member(device)
          }.bind(this))
        })
        .catch(error => {
          if (error.response.status == 403) {
            this.get_nw_own_members()
          }
        })
    },
    get_nw_own_members() {
      this.requested_members = true
      path = "/network/" + this.nw.id + "/own_member"
      axios
        .get(this.$restApi + this.controller + path, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw_members = {}
          response.data.forEach(function (deviceId) {
            device = {id: deviceId, revision: 0}
            this.nw_members[deviceId] = device
            this.get_nw_own_member(device)
          }.bind(this))
        })
        .catch(error => {
          console.log('get_nw_own_members', error)
        })
    },
    get_nw_member(device) {
      if (!this.system_network) {
        path = "/own_network/" + this.nw.id + "/member/"
      } else {
        path = "/network/" + this.nw.id + "/member/"
      }
      axios
        .get(this.$restApi + this.controller + path + device.id, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw_members[device.id] = response.data
          this.nw_member_seq_inc()
        })
        .catch(error => {
          if (error.response.status == 403) {
            this.get_nw_own_member(device)
          } else {
            console.log('get_nw_member', error)
          }
        })
    },
    get_nw_own_member(device) {
      path = "/network/" + this.nw.id + "/own_member/"
      axios
        .get(this.$restApi + this.controller + path + device.id, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw_members[device.id] = response.data
          this.nw_member_seq_inc()
        })
        .catch(error => {
          console.log('get_nw_own_member', error)
        })
    },
    authorize_nw_member(device) {
      axios
        .post(this.$restApi + this.controller + "/network/" + this.nw.id + "/member/" + device.id + "/authorize", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
        })
        .catch(error => {
          if (error.response.status == 403) {
            this.authorize_nw_own_member(device)
          } else {
            console.log('authorize_nw_member', error)
          }
        })
        .finally(() => this.get_nw_member(device))
    },
    authorize_nw_own_member(device) {
      axios
        .post(this.$restApi + this.controller + "/network/" + this.nw.id + "/own_member/" + device.id + "/authorize", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
        })
        .catch(error => {
          console.log(error)
        })
        .finally(() => this.get_nw_own_member(device))
    },
    deauthorize_nw_member(device) {
      axios
        .post(this.$restApi + this.controller + "/network/" + this.nw.id + "/member/" + device.id + "/deauthorize", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
        })
        .catch(error => {
          if (error.response.status == 403) {
            this.authorize_nw_own_member(device)
          } else {
            console.log('deauthorize_nw_member', error)
          }
        })
        .finally(() => this.get_nw_member(device))
    },
    deauthorize_nw_own_member(device) {
      axios
        .post(this.$restApi + this.controller + "/network/" + this.nw.id + "/own_member/" + device.id + "/deauthorize", {}, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
        })
        .catch(error => {
          console.log(error)
        })
        .finally(() => this.get_nw_own_member(device))
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
