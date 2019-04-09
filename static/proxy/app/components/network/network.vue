<template>

<div v-if="show_network">

  <section v-if="errored">
    <p>We're sorry, we're not able to retrieve this
       information at the moment, please try back later</p>
  </section>

  <section v-if="!errored">

    <b-jumbotron :header="nw.name" :lead="nw.id" >
     <p>{{ nw.description }}</p>
     <b-btn variant="primary" href="#">More Info</b-btn>
    </b-jumbotron>

  </section>

</div>

</template>

<script>

module.exports = {
  computed: {
    show_network() {
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
      info: null,
      loading: false,
      errored: false,
      nw: this.network
    }
  },
  props: ["network", "index", "networks", "controller", "creds", "nw_regex"],
  mounted () {
    if (!this.network.name) {
      this.load()
    }
  },
  methods: {
    load() {
      this.loading = true
      axios
        .get(this.$restApi + this.controller + "/network/" + this.network.id, {
          headers: {'X-ZTC-Token': this.creds.token.id }
        })
        .then(response => {
          this.nw = response.data
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
