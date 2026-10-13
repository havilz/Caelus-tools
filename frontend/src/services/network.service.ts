import { apiClient } from './api';
import { APIResponse } from '@/types/api';

export interface VirtualNetwork {
  id: string;
  name: string;
  type: 'vpc' | 'bridge' | 'overlay';
  cidr: string;
  gateway: string;
  region: string;
  driver?: string;
  status: 'active' | 'provisioning' | 'idle' | 'error';
  attached_servers?: number;
  attachedServers?: number;
  created_at?: string;
  createdAt?: string;
}

export interface FirewallRule {
  id: string;
  network_id?: string;
  server_id?: string;
  targetNetworkId?: string;
  name: string;
  direction: 'inbound' | 'outbound';
  protocol: 'tcp' | 'udp' | 'icmp' | 'all';
  port_range?: string;
  portRange?: string;
  source: string;
  action: 'allow' | 'deny';
  status?: string;
  created_at?: string;
}

export interface CreateNetworkRequest {
  name: string;
  type: 'vpc' | 'bridge' | 'overlay';
  cidr: string;
  gateway?: string;
  region: string;
  driver?: string;
}

export interface CreateFirewallRuleRequest {
  network_id?: string;
  server_id?: string;
  name: string;
  direction: 'inbound' | 'outbound';
  protocol: 'tcp' | 'udp' | 'icmp' | 'all';
  port_range: string;
  source: string;
  action: 'allow' | 'deny';
}

export const networkService = {
  async listNetworks(): Promise<VirtualNetwork[]> {
    const response = await apiClient.get<APIResponse<VirtualNetwork[]>>('/networks');
    return response.data.data || [];
  },

  async createNetwork(data: CreateNetworkRequest): Promise<VirtualNetwork> {
    const response = await apiClient.post<APIResponse<VirtualNetwork>>('/networks', data);
    return response.data.data;
  },

  async deleteNetwork(id: string): Promise<void> {
    await apiClient.delete(`/networks/${id}`);
  },

  async listFirewallRules(): Promise<FirewallRule[]> {
    const response = await apiClient.get<APIResponse<FirewallRule[]>>('/firewall-rules');
    return response.data.data || [];
  },

  async createFirewallRule(data: CreateFirewallRuleRequest): Promise<FirewallRule> {
    const response = await apiClient.post<APIResponse<FirewallRule>>('/firewall-rules', data);
    return response.data.data;
  },

  async deleteFirewallRule(id: string): Promise<void> {
    await apiClient.delete(`/firewall-rules/${id}`);
  },
};
