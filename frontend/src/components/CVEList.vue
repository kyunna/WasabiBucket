<template>
  <div>
    <h1 class="clickable" @click="resetList">CVE List</h1>
    <div class="search-container">
      <el-input
        v-model="searchQuery"
        placeholder="CVE ID 검색"
        class="search-input"
        clearable
        @keyup.enter="handleSearch"
      >
        <template #append>
          <el-button @click="handleSearch">
            검색
          </el-button>
        </template>
      </el-input>
    </div>
    <el-table
      v-loading="loading"
      :data="cves"
      style="width: 100%"
      @row-click="showDetail"
      @sort-change="handleSortChange"
    >
    <el-table-column prop="published_date" label="등록일" width="120" sortable="custom">
      <template #default="scope">
        {{ formatDate(scope.row.published_date) }}
      </template>
    </el-table-column>
    <el-table-column prop="last_modified_date" label="갱신일" width="120" sortable="custom">
      <template #default="scope">
        {{ formatDate(scope.row.last_modified_date) }}
      </template>
    </el-table-column>
      <el-table-column prop="cve_id" label="CVE ID" width="140" />
      <el-table-column prop="vulnerability_status" label="상태" width="100" />
      <el-table-column prop="analysis_summary" label="분석 요약" min-width="200">
        <template #default="scope">
          <el-tooltip :content="scope.row.analysis_summary" placement="top" :hide-after="0">
            <span>{{ truncateText(scope.row.analysis_summary, 100) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="risk_level" label="위험도" width="80">
        <template #default="scope">
          <el-tooltip :content="getRiskLevel(scope.row.risk_level)" placement="top">
            <el-image
              :src="getRiskLevelIcon(scope.row.risk_level)"
              :alt="getRiskLevel(scope.row.risk_level)"
              style="width: 20px; height: 20px;"
            />
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="affected_products" label="영향받는 제품명" min-width="150">
        <template #default="scope">
          <el-tooltip :content="scope.row.affected_products?.join(', ')" placement="top" :hide-after="0">
            <span>{{ formatAffectedProducts(scope.row.affected_products) }}</span>
          </el-tooltip>
        </template>
      </el-table-column>
      <el-table-column prop="analysis_updated_at" label="최종 분석일" width="160" sortable="custom">
      <template #default="scope">
        {{ formatDateTime(scope.row.analysis_updated_at) }}
      </template>
    </el-table-column>
      <el-table-column label="분석" width="80">
        <template #default="scope">
          <el-image
            :src="scope.row.analysis_summary ? getRetryIcon() : getPlayIcon()"
            :alt="scope.row.analysis_summary ? '재분석' : '분석'"
            style="width: 24px; height: 24px; cursor: pointer;"
            @click="requestAnalysis(scope.row.cve_id)"
          />
        </template>
      </el-table-column>
    </el-table>

    <div class="pagination-container">
      <el-pagination
        v-model:current-page="currentPage"
        :page-size="20"
        :total="pagination?.totalCount || 0"
        @current-change="handleCurrentChange"
        layout="total, prev, pager, next, jumper"
      />
    </div>

    <CVEDetailModal
      v-model:show="showModal"
      :cve-id="selectedCveId"
    />
  </div>
</template>

<script>
import { ref, onMounted } from 'vue'
import { ElMessage } from 'element-plus'
import axios from 'axios'
import CVEDetailModal from './CVEDetailModal.vue'

export default {
  components: {
    CVEDetailModal
  },
  setup() {
    const cves = ref([])
    const pagination = ref(null)
    const currentPage = ref(1)
    const loading = ref(false)
    const showModal = ref(false)
    const selectedCveId = ref(null)
    const searchQuery = ref('')
    const sortBy = ref('')
    const sortOrder = ref('')

    const fetchCVEs = async (page = 1, search = '', sort = '') => {
    loading.value = true
    try {
      const url = new URL('https://k07yvmvs4c.execute-api.ap-northeast-2.amazonaws.com/cve')
      const params = new URLSearchParams({ page: page.toString() })
      
      if (search) params.append('cveId', search)
      if (sort) {
        params.append('sortBy', sortBy.value)
        params.append('sortOrder', sortOrder.value)
      }
      
      url.search = params.toString()
      const response = await axios.get(url.toString())
      cves.value = response.data.data
      pagination.value = response.data.pagination
    } catch (error) {
      console.error('CVE 데이터를 불러오는 중 오류가 발생했습니다:', error)
      ElMessage.error('데이터를 불러오는 데 실패했습니다.')
    } finally {
      loading.value = false
    }
  }

    const handleCurrentChange = (val) => {
      fetchCVEs(val)
    }

    const formatDate = (dateString) => {
      if (!dateString) return '-'
      const date = new Date(dateString)
      const year = date.toLocaleDateString('en-US', { year: 'numeric' })
      const month = date.toLocaleDateString('en-US', { month: '2-digit' })
      const day = date.toLocaleDateString('en-US', { day: '2-digit' })

      return `${year}-${month}-${day}`
    }

    const formatDateTime = (dateString) => {
      if (!dateString) return '-'
      const date = new Date(dateString)
      const year = date.toLocaleString('en-US', { year: 'numeric' })
      const month = date.toLocaleString('en-US', { month: '2-digit' })
      const day = date.toLocaleString('en-US', { day: '2-digit' })
      const hour = date.toLocaleString('en-US', { hour: '2-digit', hour12: false })
      const minute = date.getMinutes().toString().padStart(2, '0')
      const second = date.getSeconds().toString().padStart(2, '0')

      return `${year}-${month}-${day} ${hour}:${minute}:${second}`
    }

    const truncateText = (text, length) => {
      if (!text) return '-'
      return text.length > length ? text.substring(0, length) + '...' : text
    }

    const formatAffectedProducts = (products) => {
      if (!products) return '-'
      if (products.length === 0) return '-'
      if (products.length === 1) return products[0]
      return `${products[0]} 외`
    }

    const requestAnalysis = async (cveId) => {
      try {
        await axios.post('https://k07yvmvs4c.execute-api.ap-northeast-2.amazonaws.com/analyze', {
          cveId: cveId
        })
        ElMessage.success('분석 요청이 성공적으로 전송되었습니다.')
      } catch (error) {
        console.error('분석 요청 중 오류가 발생했습니다:', error)
        ElMessage.error('분석 요청 중 오류가 발생했습니다.')
      }
    }

    const getRiskLevel = (level) => {
      const levels = {
        '0': 'LOW',
        '1': 'MEDIUM',
        '2': 'HIGH'
      }
      return levels[level] || '알 수 없음'
    }

    const getRiskLevelIcon = (level) => {
      const icons = {
        '0': require('@/assets/risk_low.svg'),
        '1': require('@/assets/risk_medium.svg'),
        '2': require('@/assets/risk_high.svg')
      }
      return icons[level] || require('@/assets/risk_unknown.svg')
    }

    const getPlayIcon = () => {
      return require('@/assets/play.png')
    }

    const getRetryIcon = () => {
      return require('@/assets/retry.png')
    }

    const showDetail = (row) => {
      selectedCveId.value = row.cve_id
      showModal.value = true
    }

    const handleSearch = () => {
      if (searchQuery.value.trim()) {
        fetchCVEs(1, searchQuery.value.trim())
      } else {
      fetchCVEs(1)
    }
      currentPage.value = 1
    }

    // 정렬 이벤트 핸들러 추가
  const handleSortChange = ({ prop, order }) => {
    sortBy.value = prop
    sortOrder.value = order === 'ascending' ? 'asc' : 'desc'
    fetchCVEs(currentPage.value, searchQuery.value, true)
  }

  // 리스트 초기화 함수 추가
  const resetList = () => {
    searchQuery.value = ''
    sortBy.value = ''
    sortOrder.value = ''
    currentPage.value = 1
    fetchCVEs()
  }

    onMounted(() => fetchCVEs())

    return {
      cves,
      pagination,
      currentPage,
      loading,
      formatDate,
      formatDateTime,
      truncateText,
      formatAffectedProducts,
      requestAnalysis,
      handleCurrentChange,
      getRiskLevel,
      getRiskLevelIcon,
      getPlayIcon,
      getRetryIcon,
      showModal,
      selectedCveId,
      showDetail,
      searchQuery,
      handleSearch,
      handleSortChange,
      resetList,
    }
  }
}
</script>

<style scoped>
.search-container {
  margin-bottom: 20px;
  display: flex;
  justify-content: center;
}

.search-input {
  width: 400px;
}

.pagination-container {
  margin-top: 20px;
  display: flex;
  justify-content: center;
}

.clickable {
  cursor: pointer;
}
</style>