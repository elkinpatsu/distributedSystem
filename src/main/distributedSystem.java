// HOLA

package main;

import java.io.*;
import java.net.*;
import java.util.*;
import java.util.List;
import java.util.Timer;
import java.util.concurrent.*;
import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.awt.*;
import java.awt.event.*;
import java.lang.management.ManagementFactory;
import com.sun.management.OperatingSystemMXBean;

public class distributedSystem extends JFrame {
    private JButton switchButton;
    private static Socket socket;
    private static PrintWriter out;
    private static BufferedReader in;
    private static ServerSocket serverSocket;
    private static List<PrintWriter> clients = new ArrayList<>();
    private static List<Socket> clientSockets = new ArrayList<>();
    private static ArrayList<String[]> DataClients = new ArrayList<>();
    private static String clientIP = "25.53.178.157";
    private DefaultTableModel tableModel;
    private JTable table;
    private Timer timer;
    private boolean isServerMode = true; // Inicia en modo servidor
    private static ScheduledExecutorService executor;
    private static String[] serverIPs = {"25.57.124.131", "25.13.41.150", "25.53.178.157", "25.53.225.158", "25.42.108.158"}; // Lista de direcciones IP del servidor
    private static int currentServerIndex = 0;
    private ScheduledExecutorService metricSenderExecutor;
    private static String []metricasEstaticas = new String[6]; 
    private JTable detailedTable;
    private DefaultTableModel detailedModel;

    public static void main(String[] args) {
        ScheduledExecutorService scheduler = Executors.newScheduledThreadPool(1);
        Runnable connectionChecker = new Runnable() {
            public void run() {
                if (isServerAvailable(clientIP, 9999, 3000)) {
                    System.out.println("Servidor está en línea.");
                } else {
                    System.out.println("Servidor está fuera de línea.");
                    reconnectToNextServer();
                }
            }
        };

        if (args.length > 0) {
            clientIP = args[0];
        } else {
            clientIP = "25.53.178.157"; // IP predeterminada si no se proporciona ninguna
        }

        SwingUtilities.invokeLater(() -> {	
        	distributedSystem node = new distributedSystem();
            node.setVisible(true);
        });
        
        scheduler.scheduleAtFixedRate(connectionChecker, 0, 10, TimeUnit.SECONDS);

    }

    public distributedSystem() {
        super("Network Node");
        setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
        setSize(1200, 600);
        setupUI();
        if (isServerMode) {
            try {
                startServer();
            } catch (IOException e) {
                e.printStackTrace();
            }
        } else {
            try {
                startClient(clientIP, 9999);
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    private void setupUI() {
        JPanel panel = new JPanel();
        add(panel);

        switchButton = new JButton("Switch to Client");
        switchButton.addActionListener(e -> {
            try {
                switchMode();
            } catch (IOException ex) {
                ex.printStackTrace();
            }
        });
        panel.add(switchButton);

        // Table for server mode
        String[] columns = {"IP", "CPU FREE(%)", "MEMORY FREE(%)", "DISK FREE(%)", "RANKSCORE", "ESTATUS"};
        tableModel = new DefaultTableModel(columns, 0);
        table = new JTable(tableModel);
        
        // Crear el modelo de la tabla para información detallada
        String[] detailedColumnNames = { "dispositivo",
            "Procesador", "Velocidad", "Nucleos", "Almacenamiento",
            "OSVersion"
	        };

        Object[] row1 = {
        		System.getProperty("user.name"), getSystemInfo("wmic cpu get name"), getSystemInfo("wmic cpu get MaxClockSpeed"),
        		Runtime.getRuntime().availableProcessors(), new File("/").getTotalSpace() / (1024 * 1024 * 1024) + " GB",
        		getSystemInfo("wmic os get Version")
            };
        metricasEstaticas[0] = System.getProperty("user.name");
        metricasEstaticas[1] = getSystemInfo("wmic cpu get name");
        metricasEstaticas[2] = getSystemInfo("wmic cpu get MaxClockSpeed");
        metricasEstaticas[3] = Runtime.getRuntime().availableProcessors()+"";
        metricasEstaticas[4] = new File("/").getTotalSpace() / (1024 * 1024 * 1024) + " GB";
        metricasEstaticas[5] = getSystemInfo("wmic os get Version");
        detailedModel = new DefaultTableModel(detailedColumnNames, 0);
        
        detailedModel.addRow(row1);

        detailedTable = new JTable(detailedModel);
        JScrollPane detailedScrollPane = new JScrollPane(detailedTable);

        // Crear un panel para las tablas y agregar las tablas al panel
        JPanel tablePanel = new JPanel(new GridLayout(2, 1)); // 2 filas, 1 columna
        tablePanel.add(detailedScrollPane);

        
        panel.add(new JScrollPane(table));
        panel.add(new JScrollPane(detailedTable));
    }
    
    private String getSystemInfo(String command) {
        try {
            Process process = Runtime.getRuntime().exec(command);
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line;
            while ((line = reader.readLine()) != null) {
                if (!line.isEmpty() && !line.contains("Name") && !line.contains("MaxClockSpeed") && !line.contains("Version")) {
                    return line.trim();
                }
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return "Unknown";
    }


    private void switchMode() throws IOException {
        if (isServerMode) {
            // Modo servidor a cliente
            //notifyClientsToSwitch(clientIP);
            stopServer();
            resetTable();
            startClient(clientIP, 9999);
            switchButton.setText("Switch to Server");
            isServerMode = false;
            startSendingMetrics();
        } else {
            // Modo cliente a servidor
            notifyServerSwitching();
            stopClient();
            startServer();
            resetTable();
            switchButton.setText("Switch to Client");
            isServerMode = true;
            stopSendingMetrics();
        }
    }

    private void notifyServerSwitching() throws IOException {
        if (out != null) {
            out.println("SWITCHING_TO_SERVER " + socket.getLocalAddress().getHostAddress());
        }
    }

    private void notifyClientsToSwitch(String newServerIP) {
        for (PrintWriter client : clients) {
            client.println("SWITCH_TO_NEW_SERVER " + newServerIP);
        }
    }

    private void startServer() throws IOException {
        serverSocket = new ServerSocket(9999);
        executor = Executors.newScheduledThreadPool(10);
        executor.scheduleAtFixedRate(() -> {
            try {
                Socket clientSocket = serverSocket.accept();
                clientSockets.add(clientSocket);
                PrintWriter clientOut = new PrintWriter(clientSocket.getOutputStream(), true);
                clients.add(clientOut);
                new Thread(new ClientHandler(clientSocket)).start();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }, 0, 1, TimeUnit.SECONDS);
    }

    private void stopServer() throws IOException {
        if (serverSocket != null) {
            serverSocket.close();
            for (Socket clientSocket : clientSockets) {
                clientSocket.close();
            }
            clients.clear();
            clientSockets.clear();
            executor.shutdown();
        }
    }

    private static void startClient(String serverIP, int port) throws IOException {
        try {
            socket = new Socket(serverIP, port);
            out = new PrintWriter(socket.getOutputStream(), true);
            in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            new Thread(() -> {
                try {
                    String message;
                    while ((message = in.readLine()) != null) {
                        processServerMessage(message);
                    }
                } catch (IOException e) {
                    reconnectToNextServer();
                }
            }).start();
        } catch (IOException e) {
            reconnectToNextServer();
        }
    }

    private static void stopClient() throws IOException {
        if (socket != null) {
            socket.close();
            out.close();
            in.close();
        }
    }

    private static void reconnectToNextServer() {
        currentServerIndex = (currentServerIndex + 1) % serverIPs.length;
        String nextServerIP = serverIPs[currentServerIndex];
        try {
            startClient(nextServerIP, 9999);
        } catch (IOException e) {
            e.printStackTrace();
            reconnectToNextServer(); // Reintenta con la siguiente IP
        }
    }

    private static void processServerMessage(String message) {
        if (message.startsWith("SWITCH_TO_NEW_SERVER")) {
            String[] parts = message.split(" ");
            if (parts.length == 2) {
                String newServerIP = parts[1];
                switchToNewServer(newServerIP);
            }
        }
    }

    private static void switchToNewServer(String newServerIP) {
        try {
            stopClient();
            startClient(newServerIP, 9999);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static boolean isServerAvailable(String ip, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    private void startSendingMetrics() {
        metricSenderExecutor = Executors.newSingleThreadScheduledExecutor();
        metricSenderExecutor.scheduleAtFixedRate(() -> {
            if (out != null) {
                out.println(updateSystemMetrics());
            }
        }, 0, 1, TimeUnit.SECONDS);
    }

    private void stopSendingMetrics() {
        if (metricSenderExecutor != null) {
            metricSenderExecutor.shutdown();
        }
    }

    public static String getHamachiIP() {
        try {
            Enumeration<NetworkInterface> interfaces = NetworkInterface.getNetworkInterfaces();
            while (interfaces.hasMoreElements()) {
                NetworkInterface networkInterface = interfaces.nextElement();
                if (networkInterface.isUp() && !networkInterface.isLoopback()) {
                    if (networkInterface.getDisplayName().contains("Hamachi")) {
                        Enumeration<InetAddress> addresses = networkInterface.getInetAddresses();
                        while (addresses.hasMoreElements()) {
                            InetAddress address = addresses.nextElement();
                            if (address.getAddress().length == 4) { // Check if it's IPv4
                                return address.getHostAddress();
                            }
                        }
                    }
                }
            }
        } catch (SocketException e) {
            e.printStackTrace();
        }
        return null;
    }

    private static String updateSystemMetrics() {
        OperatingSystemMXBean osBean = (OperatingSystemMXBean) ManagementFactory.getOperatingSystemMXBean();
        double cpuLoad = osBean.getSystemCpuLoad() * 100;
        double cpuFree = 100 - cpuLoad;
        long freePhysicalMemorySize = osBean.getFreePhysicalMemorySize();
        long totalPhysicalMemorySize = osBean.getTotalPhysicalMemorySize();
        double memoryFreePercentage = (double) freePhysicalMemorySize / totalPhysicalMemorySize * 100;
        File disk = new File("/");
        long freeDiskSpace = disk.getFreeSpace();
        long totalDiskSpace = disk.getTotalSpace();
        double diskFreePercentage = (double) freeDiskSpace / totalDiskSpace * 100;
        double rankScore = (cpuFree + memoryFreePercentage + diskFreePercentage + Runtime.getRuntime().availableProcessors() * 100) / 100;

        return getHamachiIP() + "," + cpuFree + "," + memoryFreePercentage + "," + diskFreePercentage + "," + rankScore + ",false"+"-"+metricasEstaticas[0]+","+metricasEstaticas[1]+","+metricasEstaticas[2]+","+metricasEstaticas[3]+","+metricasEstaticas[4]+","+metricasEstaticas[5]+",";
    }

    private void addMetricsToTable(String[] metrics, String[] staticMetrics) {
        SwingUtilities.invokeLater(() -> {
            boolean updated = false;
            for (int i = 0; i < tableModel.getRowCount(); i++) {
            	boolean active = !(tableModel.getValueAt(i, 2).equals(metrics[2]) && tableModel.getValueAt(i, 3).equals(metrics[3]) && tableModel.getValueAt(i, 4).equals(metrics[4]));
            	if (!active) {
                    tableModel.setValueAt("Desconectado", i, 5);
            	} else {
                    tableModel.setValueAt("Conectado", i, 5);
            	}
            	if (tableModel.getValueAt(i, 0).equals(metrics[0])) {
                    tableModel.setValueAt(metrics[1], i, 1);
                    tableModel.setValueAt(metrics[2], i, 2);
                    tableModel.setValueAt(metrics[3], i, 3);
                    tableModel.setValueAt(metrics[4], i, 4);
                    updated = true;
                    break;
                }
            }
            if (!updated) {
                tableModel.addRow(metrics);
            }
            updated = false;
            for (int i = 0; i < detailedModel.getRowCount(); i++) {
            	if (detailedModel.getValueAt(i, 0).equals(staticMetrics[0])) {
            		detailedModel.setValueAt(staticMetrics[0], i, 0);
                    detailedModel.setValueAt(staticMetrics[1], i, 1);
                    detailedModel.setValueAt(staticMetrics[2], i, 2);
                    detailedModel.setValueAt(staticMetrics[3], i, 3);
                    detailedModel.setValueAt(staticMetrics[4], i, 4);
                    detailedModel.setValueAt(staticMetrics[5], i, 5);
                    updated = true;
                    break;
                }
            }
            if (!updated) {
            	detailedModel.addRow(staticMetrics);
            }

            sortTableByRankScore();
        });
    }

    private void sortTableByRankScore() {
        List<String[]> tableData = new ArrayList<>();
        for (int i = 0; i < tableModel.getRowCount(); i++) {
            String[] row = new String[tableModel.getColumnCount()];
            for (int j = 0; j < tableModel.getColumnCount(); j++) {
                row[j] = tableModel.getValueAt(i, j).toString();
            }
            tableData.add(row);
        }
        tableData.sort((a, b) -> Double.compare(Double.parseDouble(b[4]), Double.parseDouble(a[4])));
        tableModel.setRowCount(0); // Clear the table
        for (String[] row : tableData) {
            tableModel.addRow(row);
        }
    }

    private void resetTable() {
        SwingUtilities.invokeLater(() -> tableModel.setRowCount(0));
        SwingUtilities.invokeLater(() -> detailedModel.setRowCount(0));
        Object[] row1 = {
        		System.getProperty("user.name"), getSystemInfo("wmic cpu get name"), getSystemInfo("wmic cpu get MaxClockSpeed"),
        		Runtime.getRuntime().availableProcessors(), new File("/").getTotalSpace() / (1024 * 1024 * 1024) + " GB",
        		getSystemInfo("wmic os get Version")
            };
        SwingUtilities.invokeLater(() -> detailedModel.addRow(row1));
    }

    private class ClientHandler implements Runnable {
        private Socket socket;
        private BufferedReader in;
		private Timer timer;

        public ClientHandler(Socket socket) {
            this.socket = socket;
            try {
                this.in = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            } catch (IOException e) {
                e.printStackTrace();
            }
            this.timer = new Timer();
            resetTimer();
        }

        @Override
        public void run() {
            try {
                String message;
                while ((message = in.readLine()) != null) {
                    resetTimer();
                    if (message.equals("SWITCH_TO_SERVER")) {
                        SwingUtilities.invokeLater(() -> {
							try {
								switchMode();
							} catch (IOException e) {
								// TODO Auto-generated catch block
								e.printStackTrace();
							}
						});
                    } else {
                        processClientData(message.split("-")[0].split(","),message.split("-")[1].split(","));
                    }
                }
            } catch (IOException e) {
                e.printStackTrace();
            } finally {
                try {
                    socket.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
                clients.remove(socket);
            }
        }

        private void resetTimer() {
            timer.cancel();
            timer = new Timer();
            timer.schedule(new TimerTask() {
                @Override
                public void run() {
                    markClientAsNull();
                }
            }, 3000);
        }
        
        private void markClientAsNull() {
            SwingUtilities.invokeLater(() -> {
                if (!clients.isEmpty()) {
                    clients.set(clients.size() - 1, null);
                }
            });
        }

        private void processClientData(String[] clientData, String[] clientStaticData) {
            if (clientData.length == 6) {
                addMetricsToTable(clientData, clientStaticData);
            }
        }
    }
}