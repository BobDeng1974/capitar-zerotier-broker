<template>

<div v-if="show_network">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-else-if="network">

    <b-jumbotron :header="networkName" :lead="networkId" >
     <p>For more information visit website</p>
     <b-btn variant="primary" href="#">More Info</b-btn>
    </b-jumbotron>

  </section>

</div>

</template>

<script>

module.exports = {

  computed: {
    networkName() {
      if (!this.network) {
        return null
      }
      return this.network.name;
    },
    networkId() {
      return this.network.id;
    },
    show_network() {
      if (!this.network) {
        return false
      }
      if (!this.nw_filter) {
        return true
      }
      if (this.network.name.match(/this.nw_filter/)) {
        return true
      }
      if (this.network.id.match(/this.nw_filter/)) {
        return true
      }
    }
  },
  data () {
    return {
      info: null,
      loading: true,
      errored: false,
      network: null
    }
  },
  props: ["id", "index", "networks", "controller", "creds", "nw_filter"],
  mounted () {
    axios
      .get(this.$restApi + this.controller + "/network/" + this.id, {
        headers: {'X-ZTC-Token': this.creds.token.id }
      })
      .then(response => {
        this.network = response.data
      })
      .catch(error => {
        console.log(error)
        this.errored = true
      })
      .finally(() => this.loading = false)
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
