<template>
<div>

  <b-alert class="col-6" :show="errored">
     <b-container>
       <b-row>
         <b-col cols=3>Error status:</b-col>
         <b-col cols=9> {{ err_status }} </b-col>
       </b-row>
       <b-row>
         <b-col cols=3>Error message:</b-col>
         <b-col cols=9> {{ err_msg }} </b-col>
       </b-row>
     </b-container>
  </b-alert>

</div>
</template>


<script>
module.exports = {
  props: ["err_resp"],
  computed: {
    errored () {
      if (this.err_resp) {
        return true
      }
      return false
    },
    err_status() {
      if (!this.err_resp) {
        return 0
      }
      if (this.err_resp.data && this.err_resp.data.status) {
        return this.err_resp.data.status
      }
      if (this.err_resp.status) {
        return this.err_resp.status
      }
      return 0
    },
    err_msg() {
      if (!this.err_resp) {
        return ""
      }
      if (this.err_resp.data && this.err_resp.data.message) {
        return this.err_resp.data.message
      }
      if (this.err_resp.statusText) {
        return this.err_resp.statusText
      }
      return ""
    }
  },
}
